package prometheus_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Note that prometheus metrics are global by their nature so this is not a
// normal unit test, we create a cache middleware, emulate a query and then
// check if prom metrics were incremented.
func TestRateLimiterMetricsListener_integration_cache(t *testing.T) {
	rps := 5

	rl := ratelimit.NewBackoff(&ratelimit.BackoffConfig{
		Allowlist:            ratelimit.NewDynamicAllowlist([]netip.Prefix{}, []netip.Prefix{}),
		Period:               time.Minute,
		Duration:             time.Minute,
		Count:                rps,
		ResponseSizeEstimate: 1000,
		IPv4RPS:              rps,
		IPv6RPS:              rps,
		RefuseANY:            true,
	})
	rlMw, err := ratelimit.NewMiddleware(rl, nil)
	require.NoError(t, err)
	rlMw.Metrics = prometheus.NewRateLimitMetricsListener()

	handlerWithMiddleware := dnsserver.WithMiddlewares(
		dnsservertest.DefaultHandler(),
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
		if i < rps {
			dnsservertest.RequireResponse(t, req, nrw.Msg(), 1, dns.RcodeSuccess, false)
		} else {
			require.Nil(t, nrw.Msg())
		}
	}

	// Now make sure that prometheus metrics were incremented properly.
	requireMetrics(t, "dns_ratelimit_dropped_total")
}

func BenchmarkRateLimitMetricsListener(b *testing.B) {
	l := prometheus.NewRateLimitMetricsListener()

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
