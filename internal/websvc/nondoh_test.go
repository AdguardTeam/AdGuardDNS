package websvc_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
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

func TestService_ServeHTTP(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pt := testutil.PanicT{}

		_, err := io.WriteString(w, "[]")
		require.NoError(pt, err)
	})

	rootRedirectURL := &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   "adguard-dns.com",
		Path:   "/",
	}

	c := &websvc.Config{
		Logger:          testLogger,
		RootRedirectURL: rootRedirectURL,
		StaticContent:   http.NotFoundHandler(),
		DNSCheck:        mockHandler,
		ErrColl:         agdtest.NewErrorCollector(),
		Timeout:         testTimeout,
	}

	svc := websvc.New(c)
	require.NotNil(t, svc)

	var err error
	require.NotPanics(t, func() {
		err = svc.Start(testutil.ContextWithTimeout(t, testTimeout))
	})
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return svc.Shutdown(testutil.ContextWithTimeout(t, testTimeout))
	})

	// DNSCheck path.
	assertResponse(t, svc, "/dnscheck/test", http.StatusOK)

	// Robots path.
	assertResponse(t, svc, "/robots.txt", http.StatusOK)

	// Root redirect path.
	assertResponse(t, svc, "/", http.StatusFound)

	// Other path.
	assertResponse(t, svc, "/other", http.StatusNotFound)
}

func TestService_ServeHTTP_wellKnown(t *testing.T) {
	const (
		wellKnownHost       = "well-known.example"
		wellKnownHostPort   = wellKnownHost + ":80"
		wellKnownPathProxy  = "/.well-known/pki-validation/abcd1234"
		wellKnownPathStatic = "/.well-known/pki-validation/defg5678"
	)

	var (
		proxyBody  = []byte("well-known body")
		staticBody = []byte("static body")
	)

	var apiURL *url.URL
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pt := testutil.PanicT{}

		require.Equal(pt, apiURL.Host, r.Host)
		require.Equal(pt, wellKnownPathProxy, r.URL.Path)

		hdr := r.Header
		require.Equal(pt, agdhttp.UserAgent(), hdr.Get(httphdr.UserAgent))
		require.Equal(pt, wellKnownHost, hdr.Get(httphdr.XForwardedHost))
		require.Equal(pt, urlutil.SchemeHTTP, hdr.Get(httphdr.XForwardedProto))
		require.NotEmpty(pt, hdr.Get(httphdr.XRequestID))

		_, err := w.Write(proxyBody)
		require.NoError(pt, err)
	})

	srv := httptest.NewServer(upstream)
	apiURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	t.Cleanup(srv.Close)

	staticContent := websvc.StaticContent{
		wellKnownPathStatic: {
			Content: staticBody,
			Headers: http.Header{
				httphdr.ContentType: []string{"text/plain"},
			},
		},
	}

	c := &websvc.Config{
		Logger: testLogger,
		LinkedIP: &websvc.LinkedIPServer{
			TargetURL: apiURL,
		},
		StaticContent: staticContent,
		DNSCheck:      http.NotFoundHandler(),
		ErrColl:       agdtest.NewErrorCollector(),
		NonDoHBind: []*websvc.BindData{{
			Address: netip.MustParseAddrPort("127.0.0.1:0"),
		}},
		Timeout: testTimeout,
	}

	svc := websvc.New(c)
	require.NotNil(t, svc)

	err = svc.Start(testutil.ContextWithTimeout(t, testTimeout))
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return svc.Shutdown(testutil.ContextWithTimeout(t, testTimeout))
	})

	var addrs []net.Addr
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		addrs = svc.LocalAddrs("non_doh")
		require.Len(c, addrs, 1)
		require.NotNil(c, addrs[0])
	}, testTimeout, testTimeout/10)

	cli := &http.Client{
		Transport: &http.Transport{
			DialContext: func(
				ctx context.Context,
				network string,
				address string,
			) (c net.Conn, err error) {
				assert.Equal(t, wellKnownHost+":80", address)

				return (&net.Dialer{}).DialContext(ctx, network, addrs[0].String())
			},
		},
		Timeout: testTimeout,
	}

	require.True(t, t.Run("proxy", func(t *testing.T) {
		wkURL := &url.URL{
			Scheme: urlutil.SchemeHTTP,
			Host:   wellKnownHost,
			Path:   wellKnownPathProxy,
		}

		resp, testErr := cli.Get(wkURL.String())
		require.NoError(t, testErr)

		b, testErr := io.ReadAll(resp.Body)
		require.NoError(t, testErr)
		require.NoError(t, resp.Body.Close())

		assert.Equal(t, b, proxyBody)
	}))

	require.True(t, t.Run("static", func(t *testing.T) {
		wkURL := &url.URL{
			Scheme: urlutil.SchemeHTTP,
			Host:   wellKnownHost,
			Path:   wellKnownPathStatic,
		}

		resp, testErr := cli.Get(wkURL.String())
		require.NoError(t, testErr)

		b, testErr := io.ReadAll(resp.Body)
		require.NoError(t, testErr)
		require.NoError(t, resp.Body.Close())

		assert.Equal(t, b, staticBody)
	}))
}
