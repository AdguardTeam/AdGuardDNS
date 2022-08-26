package prometheus_test

import (
	"context"
	"net"
	"testing"

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
		MetricsListener: &prometheus.CacheMetricsListener{},
		Size:            100,
	})

	handlerWithMiddleware := dnsserver.WithMiddlewares(
		dnsservertest.DefaultHandler(),
		cacheMiddleware,
	)

	// Pass 10 requests through the middleware
	// This way we'll increment and set both hits and misses.
	for i := 0; i < 10; i++ {
		req := dnsservertest.CreateMessage("example.org.", dns.TypeA)
		addr := &net.UDPAddr{IP: net.IP{1, 2, 3, 4}, Port: 53}
		nrw := dnsserver.NewNonWriterResponseWriter(addr, addr)
		err := handlerWithMiddleware.ServeDNS(context.Background(), nrw, req)
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
