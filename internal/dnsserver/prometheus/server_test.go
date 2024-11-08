package prometheus_test

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
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
			Handler: dnsservertest.NewDefaultHandler(),
			Metrics: prometheus.NewServerMetricsListener(testNamespace),
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
	req := dnsservertest.CreateMessage(testReqDomain, dns.TypeA)

	c := &dns.Client{Net: "tcp"}

	// Send a test DNS query.
	addr := srv.LocalUDPAddr().String()

	// Pass 10 requests to make the test less flaky.
	for range 10 {
		res, _, exchErr := c.Exchange(req, addr)
		require.NoError(t, exchErr)
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

func BenchmarkServerMetricsListener(b *testing.B) {
	l := prometheus.NewServerMetricsListener(testNamespace)

	ctx := dnsserver.ContextWithServerInfo(context.Background(), testServerInfo)
	ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
		StartTime: time.Now(),
	})

	req := dnsservertest.CreateMessage(testReqDomain, dns.TypeA)
	reqSize := req.Len()

	resp := (&dns.Msg{}).SetRcode(req, dns.RcodeSuccess)
	respSize := resp.Len()

	ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
		StartTime: time.Now(),
	})

	info := &dnsserver.QueryInfo{
		Request:      req,
		Response:     resp,
		RequestSize:  reqSize,
		ResponseSize: respSize,
	}

	rw := dnsserver.NewNonWriterResponseWriter(testUDPAddr, testUDPAddr)

	b.Run("OnRequest", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			l.OnRequest(ctx, info, rw)
		}
	})

	b.Run("OnInvalidMsg", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			l.OnInvalidMsg(ctx)
		}
	})

	b.Run("OnError", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			l.OnError(ctx, nil)
		}
	})

	b.Run("OnPanic", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			l.OnPanic(ctx, nil)
		}
	})

	// Most recent result, on a ThinkPad X13 with a Ryzen Pro 7 CPU:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkServerMetricsListener/OnRequest-16                	 1550391	       716.7 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkServerMetricsListener/OnInvalidMsg-16             	13041940	        91.75 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkServerMetricsListener/OnError-16                  	12297494	        97.04 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkServerMetricsListener/OnPanic-16                  	14029394	        89.19 ns/op	       0 B/op	       0 allocs/op
}
