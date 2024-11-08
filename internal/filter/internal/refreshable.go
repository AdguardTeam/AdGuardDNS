package internal

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/ioutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/c2h5oh/datasize"
	renameio "github.com/google/renameio/v2"
)

// Refreshable contains entities common to filters that can refresh themselves
// from a file and a URL.
type Refreshable struct {
	logger    *slog.Logger
	http      *agdhttp.Client
	url       *url.URL
	id        agd.FilterListID
	cachePath string
	staleness time.Duration
	maxSize   datasize.ByteSize
}

// RefreshableConfig is the configuration structure for a refreshable filter.
type RefreshableConfig struct {
	// Logger is used to log errors during refreshes.
	Logger *slog.Logger

	// URL is the URL used to refresh the filter.  URL should be either a file
	// URL or an HTTP(S) URL and should not be nil.
	URL *url.URL

	// ID is the filter list ID for this filter.
	ID agd.FilterListID

	// CachePath is the path to the file containing the cached filter rules.
	CachePath string

	// Staleness is the time after which a file is considered stale.
	Staleness time.Duration

	// Timeout is the timeout for the HTTP client used by this refreshable
	// filter.
	Timeout time.Duration

	// MaxSize is the maximum size of the downloadable filter content.
	MaxSize datasize.ByteSize
}

// NewRefreshable returns a new refreshable filter.  c must not be nil.
func NewRefreshable(c *RefreshableConfig) (f *Refreshable, err error) {
	if c.URL == nil {
		return nil, fmt.Errorf("internal.NewRefreshable: nil url for refreshable with ID %q", c.ID)
	} else if s := c.URL.Scheme; !strings.EqualFold(s, urlutil.SchemeFile) &&
		!urlutil.IsValidHTTPURLScheme(s) {
		return nil, fmt.Errorf("internal.NewRefreshable: bad url scheme %q", s)
	}

	return &Refreshable{
		logger: c.Logger,
		http: agdhttp.NewClient(&agdhttp.ClientConfig{
			Timeout: c.Timeout,
		}),
		url:       c.URL,
		id:        c.ID,
		cachePath: c.CachePath,
		staleness: c.Staleness,
		maxSize:   c.MaxSize,
	}, nil
}

// Refresh reloads the filter data.  If acceptStale is true, refresh doesn't try
// to load the filter data from its URL when there is already a file in the
// cache directory, regardless of its staleness.
//
// TODO(a.garipov): Consider making refresh return a reader instead of a string.
func (f *Refreshable) Refresh(ctx context.Context, acceptStale bool) (text string, err error) {
	defer func() { err = errors.Annotate(err, "%s: %w", f.id) }()

	if strings.EqualFold(f.url.Scheme, urlutil.SchemeFile) {
		text, err = f.refreshFromFileOnly(ctx)
	} else {
		text, err = f.useCachedOrRefreshFromURL(ctx, acceptStale)
	}

	return text, err
}

// refreshFromFileOnly refreshes from the file in the URL.  It must only be
// called when the URL of this refreshable filter is a file URI.
func (f *Refreshable) refreshFromFileOnly(ctx context.Context) (text string, err error) {
	filePath := f.url.Path
	f.logger.InfoContext(ctx, "using data from file", "path", filePath)

	text, err = f.refreshFromFile(true, filePath, time.Time{})
	if err != nil {
		return "", fmt.Errorf("refreshing from file %q: %w", filePath, err)
	}

	return text, nil
}

// useCachedOrRefreshFromURL reloads the filter data from the cache file or the http
// URL.  If acceptStale is true, refresh doesn't try to load the filter data
// from its URL when there is already a file in the cache directory, regardless
// of its staleness.  It must only be called when the URL of this refreshable
// filter has an HTTP(S) URL.
func (f *Refreshable) useCachedOrRefreshFromURL(
	ctx context.Context,
	acceptStale bool,
) (text string, err error) {
	now := time.Now()

	text, err = f.refreshFromFile(acceptStale, f.cachePath, now)
	if err != nil {
		return "", fmt.Errorf("refreshing from cache file %q: %w", f.cachePath, err)
	}

	if text == "" {
		ru := urlutil.RedactUserinfo(f.url)
		f.logger.InfoContext(ctx, "refreshing from url", "url", ru)

		text, err = f.refreshFromURL(ctx, now)
		if err != nil {
			return "", fmt.Errorf("refreshing from url %q: %w", ru, err)
		}
	} else {
		f.logger.InfoContext(ctx, "using cached data from file", "path", f.cachePath)
	}

	return text, nil
}

// refreshFromFile loads filter data from filePath if the file's mtime shows
// that it's still fresh relative to updTime.  If acceptStale is true, and the
// file exists, the data is read from there regardless of its staleness.  If err
// is nil and text is empty, a refresh from a URL is required.
func (f *Refreshable) refreshFromFile(
	acceptStale bool,
	filePath string,
	updTime time.Time,
) (text string, err error) {
	// #nosec G304 -- Assume that filePath is always either cacheDir + a valid,
	// no-slash filter list ID or a path from the index env.
	file, err := os.Open(filePath)
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

	f.logger.InfoContext(
		ctx,
		"got data from url",
		"code", resp.StatusCode,
		"content-length", resp.ContentLength,
		"server", resp.Header.Get(httphdr.Server),
		"url", urlutil.RedactUserinfo(f.url),
	)

	err = agdhttp.CheckStatus(resp, http.StatusOK)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return "", err
	}

	b := &strings.Builder{}
	mw := io.MultiWriter(b, tmpFile)
	_, err = io.Copy(mw, ioutil.LimitReader(resp.Body, f.maxSize.Bytes()))
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
