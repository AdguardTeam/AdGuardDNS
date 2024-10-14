package prometheus_test

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/cache"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Note that prometheus metrics are global by their nature so this is not a
// normal unit test, we create a cache middleware, emulate a query and then
// check if prom metrics were incremented.
func TestCacheMetricsListener_integration_cache(t *testing.T) {
	cacheMiddleware := cache.NewMiddleware(&cache.MiddlewareConfig{
		MetricsListener: prometheus.NewCacheMetricsListener(testNamespace),
		Size:            100,
	})

	handlerWithMiddleware := dnsserver.WithMiddlewares(
		dnsservertest.DefaultHandler(),
		cacheMiddleware,
	)

	// Pass 10 requests through the middleware.  This way we'll increment and
	// set both hits and misses.
	for range 10 {
		ctx := dnsserver.ContextWithServerInfo(context.Background(), testServerInfo)
		ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
			StartTime: time.Now(),
		})

		nrw := dnsserver.NewNonWriterResponseWriter(testUDPAddr, testUDPAddr)

		req := dnsservertest.CreateMessage(testReqDomain, dns.TypeA)

		err := handlerWithMiddleware.ServeDNS(ctx, nrw, req)
		require.NoError(t, err)
		dnsservertest.RequireResponse(t, req, nrw.Msg(), 1, dns.RcodeSuccess, false)
	}

	// Now make sure that prometheus metrics were incremented properly.
	requireMetrics(
		t,
		"dns_cache_hits_total",
		"dns_cache_misses_total",
		"dns_cache_size",
	)
}
