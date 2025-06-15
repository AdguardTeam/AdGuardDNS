package websvc_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinkedIPProxy_ServeHTTP(t *testing.T) {
	t.Parallel()

	const (
		badRemoteIP = "192.0.2.2"
		receivedIP  = "127.0.0.1"
	)

	var (
		proxyAddr          *net.TCPAddr
		targetURL          *url.URL
		collectedTestNames sync.Map
	)

	upstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		pt := testutil.PanicT{}

		hdr := r.Header

		require.Equal(pt, agdhttp.UserAgent(), hdr.Get(httphdr.UserAgent))
		require.NotEmpty(pt, hdr.Get(httphdr.XRequestID))

		require.Equal(pt, targetURL.Host, r.Host)
		require.Equal(pt, receivedIP, hdr.Get(httphdr.XForwardedFor))
		require.Equal(pt, receivedIP, hdr.Get(httphdr.XConnectingIP))
		require.Equal(pt, proxyAddr.String(), hdr.Get(httphdr.XForwardedHost))
		require.Equal(pt, urlutil.SchemeHTTP, hdr.Get(httphdr.XForwardedProto))

		require.Empty(pt, hdr.Get(httphdr.CFConnectingIP))
		require.Empty(pt, hdr.Get(httphdr.Forwarded))
		require.Empty(pt, hdr.Get(httphdr.TrueClientIP))
		require.Empty(pt, hdr.Get(httphdr.XRealIP))

		collectedTestNames.Store(r.Method+" "+r.URL.Path, struct{}{})
	})

	srv := httptest.NewServer(upstream)
	t.Cleanup(srv.Close)

	targetURL, errParse := url.Parse(srv.URL)
	require.NoError(t, errParse)

	c := &websvc.Config{
		Logger:               testLogger,
		CertificateValidator: testCertValidator,
		StaticContent:        http.NotFoundHandler(),
		DNSCheck:             http.NotFoundHandler(),
		ErrColl:              agdtest.NewErrorCollector(),
		Metrics:              websvc.EmptyMetrics{},
		Timeout:              testTimeout,
		LinkedIP: &websvc.LinkedIPServer{
			TargetURL: targetURL,
			Bind: []*websvc.BindData{{
				Address: localhostZeroPort,
				TLS:     nil,
			}},
		},
	}

	svc := websvc.New(c)
	startService(t, svc)

	proxyAddr = requireServerGroupAddr(t, svc, websvc.ServerGroupLinkedIP)

	cl := http.Client{
		Timeout: testTimeout,
	}

	testCases := []struct {
		wantReceived            assert.BoolAssertionFunc
		name                    string
		method                  string
		path                    string
		wantAccessControlHdrVal string
		wantCode                int
	}{{
		wantReceived:            assert.True,
		name:                    "linkip",
		method:                  http.MethodGet,
		path:                    "/linkip/dev1234/0123456789/status",
		wantCode:                http.StatusOK,
		wantAccessControlHdrVal: agdhttp.HdrValWildcard,
	}, {
		wantReceived:            assert.True,
		name:                    "ddns",
		method:                  http.MethodPost,
		path:                    "/ddns/dev1234/0123456789/example.com",
		wantCode:                http.StatusOK,
		wantAccessControlHdrVal: agdhttp.HdrValWildcard,
	}, {
		wantReceived:            assert.False,
		name:                    "other",
		method:                  http.MethodGet,
		path:                    "/some/other/path",
		wantCode:                http.StatusNotFound,
		wantAccessControlHdrVal: "",
	}, {
		wantReceived:            assert.False,
		name:                    "robots_txt",
		method:                  http.MethodGet,
		path:                    "/robots.txt",
		wantCode:                http.StatusOK,
		wantAccessControlHdrVal: "",
	}, {
		wantReceived:            assert.False,
		name:                    "linkip_bad_path",
		method:                  http.MethodGet,
		path:                    "/linkip/dev1234/0123456789/status/more/stuff",
		wantCode:                http.StatusNotFound,
		wantAccessControlHdrVal: "",
	}, {
		wantReceived:            assert.False,
		name:                    "linkip_bad_method",
		method:                  http.MethodDelete,
		path:                    "/linkip/dev1234/0123456789/status",
		wantCode:                http.StatusNotFound,
		wantAccessControlHdrVal: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, testTimeout)

			u := &url.URL{
				Scheme: urlutil.SchemeHTTP,
				Host:   proxyAddr.String(),
				Path:   tc.path,
			}

			req, err := http.NewRequestWithContext(ctx, tc.method, u.String(), nil)
			require.NoError(t, err)

			// Set some test headers to make sure they're not proxied.
			req.Header.Set(httphdr.CFConnectingIP, badRemoteIP)
			req.Header.Set(httphdr.Forwarded, badRemoteIP)
			req.Header.Set(httphdr.TrueClientIP, badRemoteIP)
			req.Header.Set(httphdr.XForwardedFor, badRemoteIP)
			req.Header.Set(httphdr.XForwardedHost, "bad.example")
			req.Header.Set(httphdr.XForwardedProto, "foo")
			req.Header.Set(httphdr.XRealIP, badRemoteIP)

			resp, err := cl.Do(req)
			require.NoError(t, err)
			require.NotNil(t, resp, "response should not be nil")
			require.Equal(t, tc.wantCode, resp.StatusCode)

			hdr := resp.Header
			assert.Equal(t, agdhttp.UserAgent(), hdr.Get(httphdr.Server))
			assert.Equal(t, tc.wantAccessControlHdrVal, hdr.Get(httphdr.AccessControlAllowOrigin))

			_, found := collectedTestNames.Load(tc.method + " " + tc.path)
			tc.wantReceived(t, found)
		})
	}
}
