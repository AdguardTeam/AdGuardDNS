package websvc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinkedIPProxy_ServeHTTP(t *testing.T) {
	const (
		badRemoteIP = "192.0.2.2"

		realRemoteIP   = "192.0.2.1"
		realRemoteAddr = realRemoteIP + ":12345"
		realHost       = "link-ip.example"
	)

	var (
		targetURL *url.URL
		numReq    atomic.Uint64
	)

	upstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		pt := testutil.PanicT{}

		hdr := r.Header

		require.Equal(pt, agdhttp.UserAgent(), hdr.Get(httphdr.UserAgent))
		require.NotEmpty(pt, hdr.Get(httphdr.XRequestID))

		require.Equal(pt, targetURL.Host, r.Host)
		require.Equal(pt, realRemoteIP, hdr.Get(httphdr.XForwardedFor))
		require.Equal(pt, realRemoteIP, hdr.Get(httphdr.XConnectingIP))
		require.Equal(pt, realHost, hdr.Get(httphdr.XForwardedHost))
		require.Equal(pt, urlutil.SchemeHTTP, hdr.Get(httphdr.XForwardedProto))

		require.Empty(pt, hdr.Get(httphdr.CFConnectingIP))
		require.Empty(pt, hdr.Get(httphdr.Forwarded))
		require.Empty(pt, hdr.Get(httphdr.TrueClientIP))
		require.Empty(pt, hdr.Get(httphdr.XRealIP))

		numReq.Add(1)
	})

	srv := httptest.NewServer(upstream)
	t.Cleanup(srv.Close)

	targetURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	h := newLinkedIPHandler(&linkedIPHandlerConfig{
		targetURL:     targetURL,
		certValidator: nil,
		errColl:       agdtest.NewErrorCollector(),
		proxyLogger:   testLogger,
		timeout:       testTimeout,
	})

	testCases := []struct {
		name                    string
		method                  string
		path                    string
		wantAccessControlHdrVal string
		diff                    uint64
		wantCode                int
	}{{
		name:                    "linkip",
		method:                  http.MethodGet,
		path:                    "/linkip/dev1234/0123456789/status",
		diff:                    +1,
		wantCode:                http.StatusOK,
		wantAccessControlHdrVal: agdhttp.HdrValWildcard,
	}, {
		name:                    "ddns",
		method:                  http.MethodPost,
		path:                    "/ddns/dev1234/0123456789/example.com",
		diff:                    +1,
		wantCode:                http.StatusOK,
		wantAccessControlHdrVal: agdhttp.HdrValWildcard,
	}, {
		name:                    "other",
		method:                  http.MethodGet,
		path:                    "/some/other/path",
		diff:                    0,
		wantCode:                http.StatusNotFound,
		wantAccessControlHdrVal: "",
	}, {
		name:                    "robots_txt",
		method:                  http.MethodGet,
		path:                    "/robots.txt",
		diff:                    0,
		wantCode:                http.StatusOK,
		wantAccessControlHdrVal: "",
	}, {
		name:                    "linkip_bad_path",
		method:                  http.MethodGet,
		path:                    "/linkip/dev1234/0123456789/status/more/stuff",
		diff:                    0,
		wantCode:                http.StatusNotFound,
		wantAccessControlHdrVal: "",
	}, {
		name:                    "linkip_bad_method",
		method:                  http.MethodDelete,
		path:                    "/linkip/dev1234/0123456789/status",
		diff:                    0,
		wantCode:                http.StatusNotFound,
		wantAccessControlHdrVal: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testutil.ContextWithTimeout(t, testTimeout)
			ctx = slogutil.ContextWithLogger(ctx, testLogger)

			r := httptest.NewRequestWithContext(ctx, tc.method, (&url.URL{
				Scheme: urlutil.SchemeHTTP,
				Host:   realHost,
				Path:   tc.path,
			}).String(), strings.NewReader(""))

			// Set the IP address that should be proxied.
			r.RemoteAddr = realRemoteAddr

			// Set some test headers to make sure they're not proxied.
			r.Header.Set(httphdr.CFConnectingIP, badRemoteIP)
			r.Header.Set(httphdr.Forwarded, badRemoteIP)
			r.Header.Set(httphdr.TrueClientIP, badRemoteIP)
			r.Header.Set(httphdr.XForwardedFor, badRemoteIP)
			r.Header.Set(httphdr.XForwardedHost, "bad.example")
			r.Header.Set(httphdr.XForwardedProto, "foo")
			r.Header.Set(httphdr.XRealIP, badRemoteIP)

			rw := httptest.NewRecorder()

			prev := numReq.Load()
			h.ServeHTTP(rw, r)
			assert.Equal(t, prev+tc.diff, numReq.Load(), "req was not expected")
			assert.Equal(t, tc.wantCode, rw.Code)

			hdr := rw.Header()
			assert.Equal(t, agdhttp.UserAgent(), hdr.Get(httphdr.Server))
			assert.Equal(t, tc.wantAccessControlHdrVal, hdr.Get(httphdr.AccessControlAllowOrigin))
		})
	}
}
