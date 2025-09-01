package filtertest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/require"
)

// PrepareRefreshable launches an HTTP server serving the given text and code,
// as well as creates a cache file.  If reqCh not nil, a signal is sent every
// time the server is called.  The server uses [ServerName] as the value of the
// Server header.
//
// TODO(a.garipov):  Rewrite to use []byte for text.
func PrepareRefreshable(
	tb testing.TB,
	reqCh chan<- struct{},
	text string,
	code int,
) (cachePath string, srvURL *url.URL) {
	tb.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pt := testutil.PanicT{}
		if reqCh != nil {
			testutil.RequireSend(pt, reqCh, struct{}{}, Timeout)
		}

		w.Header().Set(httphdr.Server, ServerName)

		w.WriteHeader(code)

		_, writeErr := io.WriteString(w, text)
		require.NoError(pt, writeErr)
	}))
	tb.Cleanup(srv.Close)

	srvURL, err := agdhttp.ParseHTTPURL(srv.URL)
	require.NoError(tb, err)

	cacheDir := tb.TempDir()
	cacheFile, err := os.CreateTemp(cacheDir, filepath.Base(tb.Name()))
	require.NoError(tb, err)
	require.NoError(tb, cacheFile.Close())

	return cacheFile.Name(), srvURL
}
