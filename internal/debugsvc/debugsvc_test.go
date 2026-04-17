package debugsvc_test

import (
	"cmp"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/debugsvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/netutil/httputil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is a common timeout for tests.
//
// TODO(m.kazantsev):  Investigate the problem of the context timeout expiring
// when servers shutting down, when the timeout is set to a shorter duration.
const testTimeout = 7 * time.Second

// localhostAnyPort is a localhost IPv4 address with zero port for tests.
//
// TODO(m.kazantsev):  Move to golibs.
var localhostAnyPort = netip.AddrPortFrom(netutil.IPv4Localhost(), 0)

func TestService_Start_services(t *testing.T) {
	t.Parallel()

	c := &debugsvc.Config{
		APIAddr:        localhostAnyPort,
		PrometheusAddr: localhostAnyPort,
		PprofAddr:      localhostAnyPort,
	}

	svc := newTestDebugService(t, c)
	servicetest.RequireRun(t, svc, testTimeout)

	srvAddr := requireHandlerGroupAddr(t, svc, debugsvc.HandlerGroupAPI)

	client := &http.Client{
		Timeout: testTimeout,
	}

	srvURL := &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   srvAddr.String(),
	}

	// First check health-check service URL.  As the service could not be ready
	// yet, check for it in periodically.
	eventuallyCheckHealth(t, client, srvURL)

	testCases := []struct {
		name     string
		wantResp string
		basePath string
	}{{
		name:     "pprof_service",
		wantResp: "html>\n<head>\n<title>/debug/pprof/</title>",
		basePath: httputil.PprofBasePath,
	}, {
		name: "prometheus_service",
		wantResp: "# HELP go_gc_duration_seconds A summary of the wall-time pause " +
			"(stop-the-world) duration in garbage collection cycles.",
		basePath: debugsvc.PathPatternMetrics,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp, err := client.Get(srvURL.JoinPath(tc.basePath).String())
			require.NoError(t, err)

			respBody := readRespBody(t, resp)
			assert.Contains(t, respBody, tc.wantResp)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

// newTestDebugService is a helper for creating the [*debugsvc.Service]
// for tests.  c may not be nil, and all zero-values fields in c are replaced
// with defaults for tests.
func newTestDebugService(tb testing.TB, c *debugsvc.Config) (svc *debugsvc.Service) {
	tb.Helper()

	c = cmp.Or(c, &debugsvc.Config{})

	emptyAddr := netip.AddrPort{}

	c.Logger = cmp.Or(c.Logger, slogutil.NewDiscardLogger())
	c.Manager = cmp.Or(c.Manager, agdcache.NewDefaultManager())
	c.APIAddr = cmp.Or(c.APIAddr, emptyAddr)
	c.DNSDBAddr = cmp.Or(c.DNSDBAddr, emptyAddr)
	c.PprofAddr = cmp.Or(c.PprofAddr, emptyAddr)
	c.PrometheusAddr = cmp.Or(c.PrometheusAddr, emptyAddr)
	c.DNSDBHandler = cmp.Or(c.DNSDBHandler, nil)
	c.GeoIP = cmp.Or[geoip.Interface](c.GeoIP, agdtest.NewGeoIP())

	// The underlying type of Refreshers is a map, which is incomparable. That's
	// why we manually check if it is nil.
	if c.Refreshers == nil {
		c.Refreshers = debugsvc.Refreshers{}
	}

	svc = debugsvc.New(c)
	require.NotNil(tb, svc)

	return svc
}

// readRespBody is a helper function that reads and returns body from response.
func readRespBody(tb testing.TB, resp *http.Response) (body string) {
	tb.Helper()

	buf, err := io.ReadAll(resp.Body)
	require.NoError(tb, err)
	require.NoError(tb, resp.Body.Close())

	return string(buf)
}

// eventuallyCheckHealth is a helper function that waits for [*debugsvc.Service]
// to start and check it's health eventually.  client and srvURL must not be
// nil.
func eventuallyCheckHealth(
	tb testing.TB,
	client *http.Client,
	srvURL *url.URL,
) {
	tb.Helper()

	var resp *http.Response
	healthCheckURL := srvURL.JoinPath(debugsvc.PathPatternHealthCheck)
	require.EventuallyWithT(tb, func(c *assert.CollectT) {
		var getErr error
		resp, getErr = client.Get(healthCheckURL.String())
		assert.NoError(c, getErr)
	}, testTimeout, testTimeout/10)

	body := readRespBody(tb, resp)
	assert.Equal(tb, string(httputil.HealthCheckHandler), body)
	assert.Equal(tb, http.StatusOK, resp.StatusCode)
}

// requireHandlerGroupAddr is a helper function that waits for
// [*debugsvc.Service] instance getting address and returns it.  It uses
// EventuallyWithT with global testTimeout as duration.  svc must not be nil.
func requireHandlerGroupAddr(
	tb testing.TB,
	svc *debugsvc.Service,
	hg debugsvc.HandlerGroup,
) (addr net.Addr) {
	tb.Helper()

	require.EventuallyWithT(tb, func(c *assert.CollectT) {
		addr = svc.LocalAddr(hg)
		require.NotNil(c, addr)
	}, testTimeout, testTimeout/10)

	return addr
}
