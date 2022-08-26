package prometheus_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Note that prometheus metrics are global by their nature so this is not a
// normal unit test, we create a forward handler, emulate a query and then
// check if prom metrics were incremented.
func TestForwardMetricsListener_integration_request(t *testing.T) {
	srv, err := dnsservertest.RunDNSServer(dnsservertest.DefaultHandler())
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return srv.Shutdown(context.Background())
	})

	// Initialize a new forward.Handler and set the metrics listener.
	handler := forward.NewHandler(&forward.HandlerConfig{
		Address:         netip.MustParseAddrPort(srv.Addr),
		MetricsListener: prometheus.NewForwardMetricsListener(0),
	}, true)

	// Prepare a test DNS message and call the handler's ServeDNS function.
	// It will then call the metrics listener and prom metrics should be
	// incremented.
	req := dnsservertest.CreateMessage("example.org.", dns.TypeA)
	addr := srv.SrvTCP.LocalAddr()
	rw := dnsserver.NewNonWriterResponseWriter(addr, addr)

	err = handler.ServeDNS(context.Background(), rw, req)
	require.NoError(t, err)

	// Now make sure that prometheus metrics were incremented properly.
	requireMetrics(
		t,
		"dns_forward_request_total",
		"dns_forward_request_duration_seconds",
		"dns_forward_response_rcode_total",
	)
}
