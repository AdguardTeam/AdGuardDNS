package internal

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdio"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/log"
	"github.com/google/renameio"
)

// Refreshable contains entities common to filters that can refresh themselves
// from a file and a URL.
type Refreshable struct {
	// http is the HTTP client used to refresh the filter.
	http *agdhttp.Client

	// url is the URL used to refresh the filter.
	url *url.URL

	// id is the filter list ID, if any.
	id agd.FilterListID

	// cachePath is the path to the file containing the cached filter rules.
	cachePath string

	// staleness is the time after which a file is considered stale.
	staleness time.Duration
}

// NewRefreshable returns a new refreshable filter.  All parameters must be
// non-zero.
func NewRefreshable(l *agd.FilterList, cachePath string) (f *Refreshable) {
	return &Refreshable{
		http: agdhttp.NewClient(&agdhttp.ClientConfig{
			Timeout: DefaultFilterRefreshTimeout,
		}),
		url:       l.URL,
		id:        l.ID,
		cachePath: cachePath,
		staleness: l.RefreshIvl,
	}
}

// Refresh reloads the filter data.  If acceptStale is true, refresh doesn't try
// to load the filter data from its URL when there is already a file in the
// cache directory, regardless of its staleness.
func (f *Refreshable) Refresh(
	ctx context.Context,
	acceptStale bool,
) (text string, err error) {
	now := time.Now()

	defer func() { err = errors.Annotate(err, "%s: %w", f.id) }()

	text, err = f.refreshFromFile(acceptStale, now)
	if err != nil {
		return "", fmt.Errorf("refreshing from file %q: %w", f.cachePath, err)
	}

	if text == "" {
		log.Info("%s: refreshing from url %q", f.id, f.url)

		text, err = f.refreshFromURL(ctx, now)
		if err != nil {
			return "", fmt.Errorf("refreshing from url %q: %w", f.url, err)
		}
	}

	return text, nil
}

// refreshFromFile loads filter data from a file if the file's mtime shows that
// it's still fresh relative to updTime.  If acceptStale is true, and the cache
// file exists, the data is read from there regardless of its staleness.  If err
// is nil and text is empty, a refresh from a URL is required.
func (f *Refreshable) refreshFromFile(
	acceptStale bool,
	updTime time.Time,
) (text string, err error) {
	// #nosec G304 -- Assume that cachePath is always cacheDir + a valid,
	// no-slash filter list ID.
	file, err := os.Open(f.cachePath)
	if errors.Is(err, os.ErrNotExist) {
		// File does not exist.  Refresh from the URL.
		return "", nil
	} else if err != nil {
		return "", fmt.Errorf("opening filter file: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, file.Close()) }()

	if !acceptStale {
		var fi fs.FileInfo
		fi, err = file.Stat()
		if err != nil {
			return "", fmt.Errorf("reading filter file stat: %w", err)
		}

		if mtime := fi.ModTime(); !mtime.Add(f.staleness).After(updTime) {
			return "", nil
		}
	}

	b := &strings.Builder{}
	_, err = io.Copy(b, file)
	if err != nil {
		return "", fmt.Errorf("reading filter file: %w", err)
	}

	return b.String(), nil
}

// refreshFromURL loads the filter data from u, puts it into the file specified
// by cachePath, returns its content, and also sets its atime and mtime to
// updTime.
func (f *Refreshable) refreshFromURL(
	ctx context.Context,
	updTime time.Time,
) (text string, err error) {
	// TODO(a.garipov): Cache these like renameio recommends.
	tmpDir := renameio.TempDir(filepath.Dir(f.cachePath))
	tmpFile, err := renameio.TempFile(tmpDir, f.cachePath)
	if err != nil {
		return "", fmt.Errorf("creating temporary filter file: %w", err)
	}
	defer func() { err = f.withDeferredTmpCleanup(err, tmpFile, updTime) }()

	resp, err := f.http.Get(ctx, f.url)
	if err != nil {
		return "", fmt.Errorf("requesting: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, resp.Body.Close()) }()

	srv := resp.Header.Get(httphdr.Server)
	cl := resp.ContentLength

	log.Info(
		"%s: loading from %q: got content-length %d, code %d, srv %q",
		f.id,
		f.url,
		cl,
		resp.StatusCode,
		srv,
	)

	err = agdhttp.CheckStatus(resp, http.StatusOK)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return "", err
	}

	b := &strings.Builder{}
	mw := io.MultiWriter(b, tmpFile)
	_, err = io.Copy(mw, agdio.LimitReader(resp.Body, maxFilterSize))
	if err != nil {
		return "", agdhttp.WrapServerError(fmt.Errorf("reading into file: %w", err), resp)
	}

	// TODO(a.garipov): Make a more sophisticated data size ratio check.
	//
	// See AGDNS-598.
	if b.Len() == 0 {
		return "", agdhttp.WrapServerError(errors.Error("empty text, not resetting"), resp)
	}

	return b.String(), nil
}

// withDeferredTmpCleanup is a helper that performs the necessary cleanups and
// finalizations of the temporary files based on the returned error.
func (f *Refreshable) withDeferredTmpCleanup(
	returned error,
	tmpFile *renameio.PendingFile,
	updTime time.Time,
) (err error) {
	// Make sure that any error returned from here is marked as a deferred one.
	if returned != nil {
		return errors.WithDeferred(returned, tmpFile.Cleanup())
	}

	err = tmpFile.CloseAtomicallyReplace()
	if err != nil {
		return errors.WithDeferred(nil, err)
	}

	// Set the modification and access times to the moment the refresh started.
	return errors.WithDeferred(nil, os.Chtimes(f.cachePath, updTime, updTime))
}
