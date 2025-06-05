package prometheus_test

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	dnssvcprom "github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// Note that prometheus metrics are global by their nature so this is not a
// normal unit test, we run a test DNS server, send a DNS query, and then
// check that metrics were properly counted.
func TestServerMetricsListener_integration_requestLifetime(t *testing.T) {
	reg := prometheus.NewRegistry()
	mtrcListener, err := dnssvcprom.NewServerMetricsListener(testNamespace, reg)
	require.NoError(t, err)

	// Initialize the test server and supply the metrics listener.  The
	// acknowledgment-based protocol TCP is used here to make the test
	// less flaky.
	conf := &dnsserver.ConfigDNS{
		Base: &dnsserver.ConfigBase{
			BaseLogger: testLogger,
			Name:       "test",
			Addr:       "127.0.0.1:0",
			Handler:    dnsservertest.NewDefaultHandler(),
			Metrics:    mtrcListener,
		},
	}
	srv := dnsserver.NewServerDNS(conf)

	// Start the server.
	err = srv.Start(context.Background())
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
		reg,
		"dns_server_request_total",
		"dns_server_request_duration_seconds",
		"dns_server_request_size_bytes",
		"dns_server_response_size_bytes",
		"dns_server_response_rcode_total",
	)
}

func BenchmarkServerMetricsListener(b *testing.B) {
	reg := prometheus.NewRegistry()
	l, err := dnssvcprom.NewServerMetricsListener(testNamespace, reg)
	require.NoError(b, err)

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

	b.Run("on_request", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			l.OnRequest(ctx, info, rw)
		}
	})

	b.Run("on_invalid_msg", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			l.OnInvalidMsg(ctx)
		}
	})

	b.Run("on_error", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			l.OnError(ctx, nil)
		}
	})

	b.Run("on_panic", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			l.OnPanic(ctx, nil)
		}
	})

	// Most recent results:
	//
	// goos: darwin
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus
	// cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	// BenchmarkServerMetricsListener/on_request-12         	 1645694	       716.9 ns/op	       0 B/op	       0 allocs/op
	// BenchmarkServerMetricsListener/on_invalid_msg-12     	14245878	        86.15 ns/op	       0 B/op	       0 allocs/op
	// BenchmarkServerMetricsListener/on_error-12           	13631739	        88.86 ns/op	       0 B/op	       0 allocs/op
	// BenchmarkServerMetricsListener/on_panic-12           	13899312	        87.52 ns/op	       0 B/op	       0 allocs/op
}
