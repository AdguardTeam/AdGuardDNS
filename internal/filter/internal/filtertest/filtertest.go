// Package filtertest contains common constants and utilities for the internal
// filtering packages.
package filtertest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/require"
)

// BlockRule is the common blocking rule for filtering tests that blocks
// [ReqHost].
const BlockRule = "|" + ReqHost + "^"

// RemoteIP is the common client IP for filtering tests
var RemoteIP = netip.MustParseAddr("1.2.3.4")

// ReqHost is the common request host for filtering tests.
const ReqHost = "www.host.example"

// ReqFQDN is the common request FQDN for filtering tests.
const ReqFQDN = ReqHost + "."

// ServerName is the common server name for filtering tests.
const ServerName = "testServer/1.0"

// Timeout is the common timeout for filtering tests.
const Timeout = 1 * time.Second

// PrepareRefreshable launches an HTTP server serving the given text and code,
// as well as creates a cache file.  If code is zero, the server isn't started.
// If reqCh not nil, a signal is sent every time the server is called.  The
// server uses [ServerName] as the value of the Server header.
func PrepareRefreshable(
	tb testing.TB,
	reqCh chan<- struct{},
	text string,
	code int,
) (cachePath string, srvURL *url.URL) {
	tb.Helper()

	if code != 0 {
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

		var err error
		srvURL, err = agdhttp.ParseHTTPURL(srv.URL)
		require.NoError(tb, err)
	}

	cacheDir := tb.TempDir()
	cacheFile, err := os.CreateTemp(cacheDir, filepath.Base(tb.Name()))
	require.NoError(tb, err)
	require.NoError(tb, cacheFile.Close())

	return cacheFile.Name(), srvURL
}
