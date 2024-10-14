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
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/c2h5oh/datasize"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BlockRule is the common blocking rule for filtering tests that blocks
// [ReqHost].
const BlockRule = "|" + ReqHost + "^"

// Common string representations of IP adddresses.
const (
	SafeBrowsingReplIPv4Str = "192.0.2.1"
	PopupReplIPv4Str        = "192.0.2.3"
)

// Common IP addresses for tests.
var (
	SafeBrowsingReplIPv4 = netip.MustParseAddr(SafeBrowsingReplIPv4Str)
	PopupReplIPv4        = netip.MustParseAddr(PopupReplIPv4Str)
)

// RemoteIP is the common client IP for filtering tests
var RemoteIP = netip.MustParseAddr("1.2.3.4")

const (
	// ReqHost is the common request host for filtering tests.
	ReqHost = "www.host.example"

	// ReqFQDN is the FQDN version of ReqHost.
	ReqFQDN = ReqHost + "."

	// PopupBlockPageHost is the common popup block-page host for tests.
	PopupBlockPageHost = "ad-block.adguard.example"

	// PopupBlockPageFQDN is the FQDN version of PopupBlockPageHost.
	PopupBlockPageFQDN = PopupBlockPageHost + "."
)

// ServerName is the common server name for filtering tests.
const ServerName = "testServer/1.0"

// CacheTTL is the common long cache-TTL for filtering tests.
const CacheTTL = 1 * time.Hour

// Staleness is the common long staleness for filtering tests.
const Staleness = 1 * time.Hour

// Timeout is the common timeout for filtering tests.
const Timeout = 1 * time.Second

// FilterMaxSize is the maximum size of the downloadable rule-list for filtering
// tests.
const FilterMaxSize = 640 * datasize.KB

// AssertEqualResult is a test helper that compares two results taking
// [internal.ResultModifiedRequest] and its difference in IDs into account.
func AssertEqualResult(tb testing.TB, want, got internal.Result) (ok bool) {
	tb.Helper()

	wantRM, ok := want.(*internal.ResultModifiedRequest)
	if !ok {
		return assert.Equal(tb, want, got)
	}

	gotRM := testutil.RequireTypeAssert[*internal.ResultModifiedRequest](tb, got)

	return assert.Equal(tb, wantRM.List, gotRM.List) &&
		assert.Equal(tb, wantRM.Rule, gotRM.Rule) &&
		assertEqualRequests(tb, wantRM.Msg, gotRM.Msg)
}

// assertEqualRequests is a test helper that compares two DNS requests ignoring
// the ID.
//
// TODO(a.garipov): Move to golibs?
func assertEqualRequests(tb testing.TB, want, got *dns.Msg) (ok bool) {
	tb.Helper()

	if want == nil {
		return assert.Nil(tb, got)
	}

	// Use a shallow clone, because this should be enough to fix the ID.
	gotWithID := &dns.Msg{}
	*gotWithID = *got
	gotWithID.Id = want.Id

	return assert.Equal(tb, want, gotWithID)
}

// PrepareRefreshable launches an HTTP server serving the given text and code,
// as well as creates a cache file.  If reqCh not nil, a signal is sent every
// time the server is called.  The server uses [ServerName] as the value of the
// Server header.
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
