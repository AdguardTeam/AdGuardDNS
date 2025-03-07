package prometheus_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	dnssrvprom "github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// Note that prometheus metrics are global by their nature so this is not a
// normal unit test, we create a forward handler, emulate a query and then
// check if prom metrics were incremented.
func TestForwardMetricsListener_integration_request(t *testing.T) {
	srv, addr := dnsservertest.RunDNSServer(t, dnsservertest.NewDefaultHandler())
	reg := prometheus.NewRegistry()
	mtrcListener, err := dnssrvprom.NewForwardMetricsListener(testNamespace, reg, 0)
	require.NoError(t, err)

	// Initialize a new forward.Handler and set the metrics listener.
	handler := forward.NewHandler(&forward.HandlerConfig{
		Logger: testLogger,
		UpstreamsAddresses: []*forward.UpstreamPlainConfig{{
			Network: forward.NetworkAny,
			Address: netip.MustParseAddrPort(addr),
		}},
		MetricsListener: mtrcListener,
	})

	// Prepare a test DNS message and call the handler's ServeDNS function.
	// It will then call the metrics listener and prom metrics should be
	// incremented.
	req := dnsservertest.CreateMessage(testReqDomain, dns.TypeA)
	rw := dnsserver.NewNonWriterResponseWriter(srv.LocalUDPAddr(), srv.LocalUDPAddr())

	err = handler.ServeDNS(context.Background(), rw, req)
	require.NoError(t, err)

	// Now make sure that prometheus metrics were incremented properly.
	requireMetrics(
		t,
		reg,
		"dns_forward_request_total",
		"dns_forward_request_duration_seconds",
		"dns_forward_response_rcode_total",
	)
}
