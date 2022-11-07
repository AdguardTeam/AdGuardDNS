package prometheus_test

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	prom "github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Note that prometheus metrics are global by their nature so this is not a
// normal unit test, we run a test DNS server, send a DNS query, and then
// check that metrics were properly counted.
func TestServerMetricsListener_integration_requestLifetime(t *testing.T) {
	// Initialize the test server and supply the metrics listener.  The
	// acknowledgment-based protocol TCP is used here to make the test
	// less flaky.
	conf := dnsserver.ConfigDNS{
		ConfigBase: dnsserver.ConfigBase{
			Name:    "test",
			Addr:    "127.0.0.1:0",
			Handler: dnsservertest.DefaultHandler(),
			Metrics: &prom.ServerMetricsListener{},
		},
	}
	srv := dnsserver.NewServerDNS(conf)

	// Start the server.
	err := srv.Start(context.Background())
	require.NoError(t, err)

	// Make sure the server shuts down in the end.
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return srv.Shutdown(context.Background())
	})

	// Create a test message.
	req := dnsservertest.CreateMessage("example.org", dns.TypeA)

	c := &dns.Client{Net: "tcp"}

	// Send a test DNS query.
	addr := srv.LocalUDPAddr().String()

	// Pass 10 requests to make the test less flaky.
	for i := 0; i < 10; i++ {
		res, _, eerr := c.Exchange(req, addr)
		require.NoError(t, eerr)
		require.NotNil(t, res)
		require.Equal(t, dns.RcodeSuccess, res.Rcode)
	}

	// Now make sure that prometheus metrics were incremented properly.
	requireMetrics(
		t,
		"dns_server_request_total",
		"dns_server_request_duration_seconds",
		"dns_server_request_size_bytes",
		"dns_server_response_size_bytes",
		"dns_server_response_rcode_total",
	)
}
