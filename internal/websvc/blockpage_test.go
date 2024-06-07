package websvc_test

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlockPageServers(t *testing.T) {
	content := []byte("blocking page content\n")
	notFoundContent := []byte("404 page not found\n")
	robotsContent := []byte(agdhttp.RobotsDisallowAll)

	const (
		contentStatus = http.StatusInternalServerError
		faviconStatus = http.StatusNotFound
		robotsStatus  = http.StatusOK
	)

	// TODO(a.garipov): Do not use hardcoded ports.
	testCases := []struct {
		updateConfig func(c *websvc.Config, bps *websvc.BlockPageServer)
		addr         netip.AddrPort
		name         string
	}{{
		updateConfig: func(c *websvc.Config, bps *websvc.BlockPageServer) {
			c.AdultBlocking = bps
		},
		addr: netip.MustParseAddrPort("127.0.0.1:3000"),
		name: "adult_blocking",
	}, {
		updateConfig: func(c *websvc.Config, bps *websvc.BlockPageServer) {
			c.GeneralBlocking = bps
		},
		addr: netip.MustParseAddrPort("127.0.0.1:3001"),
		name: "general_blocking",
	}, {
		updateConfig: func(c *websvc.Config, bps *websvc.BlockPageServer) {
			c.SafeBrowsing = bps
		},
		addr: netip.MustParseAddrPort("127.0.0.1:3002"),
		name: "safe_browsing",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			bps := &websvc.BlockPageServer{
				Content: content,
				Bind: []*websvc.BindData{{
					TLS:     nil,
					Address: tc.addr,
				}},
			}

			conf := &websvc.Config{
				Timeout: testTimeout,
			}
			tc.updateConfig(conf, bps)

			startService(t, conf)

			assertContent(t, tc.addr, "/", contentStatus, content)
			assertContent(t, tc.addr, "/favicon.ico", faviconStatus, notFoundContent)
			assertContent(t, tc.addr, "/robots.txt", robotsStatus, robotsContent)
		})
	}
}

func TestBlockPageServers_noBlockPages(t *testing.T) {
	conf := &websvc.Config{
		Timeout: testTimeout,
	}

	svc := websvc.New(conf)
	require.NotNil(t, svc)

	require.NotPanics(t, func() {
		assert.NoError(t, svc.Start(testutil.ContextWithTimeout(t, testTimeout)))
		assert.NoError(t, svc.Shutdown(testutil.ContextWithTimeout(t, testTimeout)))
	})
}

func TestBlockPageServers_gzip(t *testing.T) {
	addr := netip.MustParseAddrPort("127.0.0.1:3001")
	content := []byte("generalBlockingContent")
	bps := &websvc.BlockPageServer{
		Content: content,
		Bind: []*websvc.BindData{{
			TLS:     nil,
			Address: addr,
		}},
	}

	conf := &websvc.Config{
		GeneralBlocking: bps,
	}

	startService(t, conf)

	c := http.Client{
		Timeout: testTimeout,
	}

	u := &url.URL{
		Scheme: "http",
		Host:   addr.String(),
		Path:   "/",
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(t, err)

	req.Header.Set(httphdr.AcceptEncoding, agdhttp.HdrValGzip)

	// First check health-check service URL.  As the service could not be ready
	// yet, check for it periodically.
	var resp *http.Response
	require.Eventually(t, func() (ok bool) {
		resp, err = c.Do(req)

		return err == nil
	}, testTimeout, testTimeout/10)

	zr, err := gzip.NewReader(resp.Body)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, zr.Close)

	body, err := io.ReadAll(zr)
	require.NoError(t, err)

	assert.Equal(t, content, body)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Equal(t, agdhttp.UserAgent(), resp.Header.Get(httphdr.Server))
	assert.Equal(t, agdhttp.HdrValGzip, resp.Header.Get(httphdr.ContentEncoding))
}
