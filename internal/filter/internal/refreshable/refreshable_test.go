package refreshable_test

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refrID is the ID of an [filter.ID] used for testing.
const refrID = "test_id"

// Default texts for tests.
const (
	testTextFile = "||filefilter.example\n"
	testTextURL  = "||urlfilter.example\n"
)

// Byte versions of default texts for tests.
var (
	testTextFileData = []byte(testTextFile)
	testTextURLData  = []byte(testTextURL)
)

func TestRefreshable_Refresh(t *testing.T) {
	testCases := []struct {
		name         string
		wantErrMsg   string
		srvText      string
		wantData     []byte
		staleness    time.Duration
		srvCode      int
		acceptStale  bool
		expectReq    bool
		useCacheFile bool
	}{{
		name:         "no_file",
		wantErrMsg:   "",
		srvText:      testTextURL,
		wantData:     testTextURLData,
		staleness:    0,
		srvCode:      http.StatusOK,
		acceptStale:  true,
		expectReq:    true,
		useCacheFile: false,
	}, {
		name: "no_file_http_empty",
		wantErrMsg: refrID + `: refreshing from url "URL": ` +
			`server "` + filtertest.ServerName + `": empty text, not resetting`,
		srvText:      "",
		wantData:     nil,
		staleness:    0,
		srvCode:      http.StatusOK,
		acceptStale:  true,
		expectReq:    true,
		useCacheFile: false,
	}, {
		name: "no_file_http_error",
		wantErrMsg: refrID + `: refreshing from url "URL": ` +
			`server "` + filtertest.ServerName + `": ` +
			`status code error: expected 200, got 500`,
		srvText:      "internal server error",
		wantData:     nil,
		staleness:    0,
		srvCode:      http.StatusInternalServerError,
		acceptStale:  true,
		expectReq:    true,
		useCacheFile: false,
	}, {
		name:         "file",
		wantErrMsg:   "",
		srvText:      "",
		wantData:     testTextFileData,
		staleness:    filtertest.Staleness,
		srvCode:      http.StatusOK,
		acceptStale:  true,
		expectReq:    false,
		useCacheFile: true,
	}, {
		name:         "file_stale",
		wantErrMsg:   "",
		srvText:      testTextURL,
		wantData:     testTextURLData,
		staleness:    -1 * time.Hour,
		srvCode:      http.StatusOK,
		acceptStale:  false,
		expectReq:    true,
		useCacheFile: true,
	}, {
		name:         "file_stale_accept",
		wantErrMsg:   "",
		srvText:      "",
		wantData:     testTextFileData,
		staleness:    -1 * time.Hour,
		srvCode:      http.StatusOK,
		acceptStale:  true,
		expectReq:    false,
		useCacheFile: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqCh := make(chan struct{}, 1)
			realCachePath, srvURL := filtertest.PrepareRefreshable(t, reqCh, tc.srvText, tc.srvCode)
			cachePath := prepareCachePath(t, realCachePath, tc.useCacheFile)

			c := &refreshable.Config{
				Logger:    slogutil.NewDiscardLogger(),
				URL:       srvURL,
				ID:        refrID,
				CachePath: cachePath,
				Staleness: tc.staleness,
				Timeout:   filtertest.Timeout,
				MaxSize:   filtertest.FilterMaxSize,
			}

			f, err := refreshable.New(c)
			require.NoError(t, err)

			ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
			gotData, err := f.Refresh(ctx, tc.acceptStale)
			if tc.expectReq {
				testutil.RequireReceive(t, reqCh, filtertest.Timeout)
			}

			// Since we only get the actual URL within the subtest, replace it
			// here and check the error message.
			if srvURL != nil {
				tc.wantErrMsg = strings.ReplaceAll(tc.wantErrMsg, "URL", srvURL.String())
			}

			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			assert.Equal(t, tc.wantData, gotData)
		})
	}
}

// prepareCachePath is a helper that either returns a non-existing file (if
// useCacheFile is false) or prepares a cache file using realCachePath and
// [testFileText].
func prepareCachePath(t *testing.T, realCachePath string, useCacheFile bool) (cachePath string) {
	t.Helper()

	if !useCacheFile {
		return filepath.Join(t.TempDir(), "does_not_exist")
	}

	err := os.WriteFile(realCachePath, testTextFileData, 0o600)
	require.NoError(t, err)

	return realCachePath
}

func TestRefreshable_Refresh_properStaleness(t *testing.T) {
	const responseDur = time.Second / 5

	reqCh := make(chan struct{})
	cachePath, addr := filtertest.PrepareRefreshable(
		t,
		reqCh,
		filtertest.RuleBlockStr,
		http.StatusOK,
	)

	c := &refreshable.Config{
		Logger:    slogutil.NewDiscardLogger(),
		URL:       addr,
		ID:        refrID,
		CachePath: cachePath,
		Staleness: filtertest.Staleness,
		Timeout:   filtertest.Timeout,
		MaxSize:   filtertest.FilterMaxSize,
	}

	f, err := refreshable.New(c)
	require.NoError(t, err)

	var now time.Time
	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
	go func() {
		<-reqCh
		now = time.Now()
		_, err = f.Refresh(ctx, false)
		<-reqCh
	}()

	// Start the refresh.
	reqCh <- struct{}{}

	// Hold the handler to guarantee the refresh will endure some time.
	time.Sleep(responseDur)

	// Continue the refresh.
	testutil.RequireReceive(t, reqCh, filtertest.Timeout)

	// Ensure the refresh finished.
	reqCh <- struct{}{}

	require.NoError(t, err)

	file, err := os.Open(cachePath)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, file.Close)

	fi, err := file.Stat()
	require.NoError(t, err)

	assert.InDelta(t, fi.ModTime().Sub(now), 0, float64(time.Millisecond))
}

func TestRefreshable_Refresh_fileURL(t *testing.T) {
	dir := t.TempDir()
	fltFile, err := os.CreateTemp(dir, filepath.Base(t.Name()))
	require.NoError(t, err)

	_, err = fltFile.Write(testTextFileData)
	require.NoError(t, err)

	require.NoError(t, fltFile.Close())

	c := &refreshable.Config{
		Logger: slogutil.NewDiscardLogger(),
		URL: &url.URL{
			Scheme: urlutil.SchemeFile,
			Path:   fltFile.Name(),
		},
		ID:        refrID,
		CachePath: fltFile.Name() + ".cache",
		Staleness: filtertest.Staleness,
		Timeout:   filtertest.Timeout,
		MaxSize:   filtertest.FilterMaxSize,
	}

	f, err := refreshable.New(c)
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
	b, err := f.Refresh(ctx, true)
	require.NoError(t, err)

	assert.Equal(t, testTextFileData, b)
}
