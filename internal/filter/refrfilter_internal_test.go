package filter

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshableFilter_RefreshFromFile(t *testing.T) {
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, t.Name())
	require.NoError(t, err)

	const defaultText = "||example.com\n"
	_, err = io.WriteString(f, defaultText)
	require.NoError(t, err)

	cachePath := f.Name()

	testCases := []struct {
		name        string
		cachePath   string
		wantText    string
		staleness   time.Duration
		acceptStale bool
	}{{
		name:        "no_file",
		cachePath:   "does_not_exist",
		wantText:    "",
		staleness:   0,
		acceptStale: true,
	}, {
		name:        "file",
		cachePath:   cachePath,
		wantText:    defaultText,
		staleness:   0,
		acceptStale: true,
	}, {
		name:        "file_stale",
		cachePath:   cachePath,
		wantText:    "",
		staleness:   -1 * time.Second,
		acceptStale: false,
	}, {
		name:        "file_stale_accept",
		cachePath:   cachePath,
		wantText:    defaultText,
		staleness:   -1 * time.Second,
		acceptStale: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := &refreshableFilter{
				http:      nil,
				url:       nil,
				id:        "test_filter",
				cachePath: tc.cachePath,
				typ:       "test filter",
				staleness: tc.staleness,
			}

			var text string
			text, err = f.refreshFromFile(tc.acceptStale)
			require.NoError(t, err)

			assert.Equal(t, tc.wantText, text)
		})
	}
}

func TestRefreshableFilter_RefreshFromURL(t *testing.T) {
	const defaultText = "||example.com\n"

	codeCh := make(chan int, 1)
	textCh := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pt := testutil.PanicT{}

		w.WriteHeader(<-codeCh)

		_, err := io.WriteString(w, <-textCh)
		require.NoError(pt, err)
	}))
	t.Cleanup(srv.Close)

	u, err := agdhttp.ParseHTTPURL(srv.URL)
	require.NoError(t, err)

	httpCli := agdhttp.NewClient(&agdhttp.ClientConfig{
		Timeout: testTimeout,
	})

	dir := t.TempDir()
	f, err := os.CreateTemp(dir, t.Name())
	require.NoError(t, err)

	_, err = io.WriteString(f, defaultText)
	require.NoError(t, err)

	cachePath := f.Name()

	testCases := []struct {
		name       string
		cachePath  string
		text       string
		wantText   string
		wantErrMsg string
		timeout    time.Duration
		code       int
		expectReq  bool
	}{{
		name:       "success",
		cachePath:  cachePath,
		text:       defaultText,
		wantText:   defaultText,
		wantErrMsg: "",
		timeout:    testTimeout,
		code:       http.StatusOK,
		expectReq:  true,
	}, {
		name:       "not_found",
		cachePath:  cachePath,
		text:       defaultText,
		wantText:   "",
		wantErrMsg: `server "": status code error: expected 200, got 404`,
		timeout:    testTimeout,
		code:       http.StatusNotFound,
		expectReq:  true,
	}, {
		name:       "timeout",
		cachePath:  cachePath,
		text:       defaultText,
		wantText:   "",
		wantErrMsg: `requesting: Get "` + u.String() + `": context deadline exceeded`,
		timeout:    0,
		code:       http.StatusOK,
		// Context deadline errors are returned before any actual HTTP
		// requesting happens.
		expectReq: false,
	}, {
		name:       "empty",
		cachePath:  cachePath,
		text:       "",
		wantText:   "",
		wantErrMsg: `server "": empty text, not resetting`,
		timeout:    testTimeout,
		code:       http.StatusOK,
		expectReq:  true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := &refreshableFilter{
				http:      httpCli,
				url:       u,
				id:        "test_filter",
				cachePath: tc.cachePath,
				typ:       "test filter",
				staleness: testTimeout,
			}

			if tc.expectReq {
				codeCh <- tc.code
				textCh <- tc.text
			}

			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()

			var text string
			text, err = f.refreshFromURL(ctx)
			assert.Equal(t, tc.wantText, text)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}
