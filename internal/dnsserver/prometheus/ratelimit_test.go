package prometheus_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	dnssvcprom "github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/c2h5oh/datasize"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// Note that prometheus metrics are global by their nature so this is not a
// normal unit test, we create a cache middleware, emulate a query and then
// check if prom metrics were incremented.
func TestRateLimiterMetricsListener_integration_cache(t *testing.T) {
	const (
		count = 5
		ivl   = time.Second
	)

	rl := ratelimit.NewBackoff(&ratelimit.BackoffConfig{
		Allowlist:            ratelimit.NewDynamicAllowlist([]netip.Prefix{}, []netip.Prefix{}),
		Period:               time.Minute,
		Duration:             time.Minute,
		Count:                count,
		ResponseSizeEstimate: 1 * datasize.KB,
		IPv4Count:            count,
		IPv4Interval:         ivl,
		IPv6Count:            count,
		IPv6Interval:         ivl,
		RefuseANY:            true,
	})

	reg := prometheus.NewRegistry()
	mtrcListener, err := dnssvcprom.NewRateLimitMetricsListener(testNamespace, reg)
	require.NoError(t, err)

	rlMw, err := ratelimit.NewMiddleware(&ratelimit.MiddlewareConfig{
		Metrics:   mtrcListener,
		RateLimit: rl,
	})
	require.NoError(t, err)

	handlerWithMiddleware := dnsserver.WithMiddlewares(
		dnsservertest.NewDefaultHandler(),
		rlMw,
	)

	// Pass 10 requests through the middleware.
	for i := range 10 {
		ctx := dnsserver.ContextWithServerInfo(context.Background(), testServerInfo)
		ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
			StartTime: time.Now(),
		})

		nrw := dnsserver.NewNonWriterResponseWriter(testUDPAddr, testUDPAddr)

		req := dnsservertest.CreateMessage(testReqDomain, dns.TypeA)

		err = handlerWithMiddleware.ServeDNS(ctx, nrw, req)
		require.NoError(t, err)
		if i < count {
			dnsservertest.RequireResponse(t, req, nrw.Msg(), 1, dns.RcodeSuccess, false)
		} else {
			require.Nil(t, nrw.Msg())
		}
	}

	// Now make sure that prometheus metrics were incremented properly.
	requireMetrics(t, reg, "dns_ratelimit_dropped_total")
}

func BenchmarkRateLimitMetricsListener(b *testing.B) {
	reg := prometheus.NewRegistry()
	l, err := dnssvcprom.NewRateLimitMetricsListener(testNamespace, reg)
	require.NoError(b, err)

	ctx := dnsserver.ContextWithServerInfo(context.Background(), testServerInfo)
	req := dnsservertest.CreateMessage(testReqDomain, dns.TypeA)
	rw := dnsserver.NewNonWriterResponseWriter(testUDPAddr, testUDPAddr)

	b.Run("OnAllowlisted", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			l.OnAllowlisted(ctx, req, rw)
		}
	})

	b.Run("OnRateLimited", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			l.OnRateLimited(ctx, req, rw)
		}
	})

	// Most recent result, on a ThinkPad X13 with a Ryzen Pro 7 CPU:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkRateLimitMetricsListener/OnAllowlisted-16         	 6025423	       209.5 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkRateLimitMetricsListener/OnRateLimited-16         	 5798031	       209.4 ns/op	       0 B/op	       0 allocs/op
}
