package prometheus_test

import (
	"context"
	"net"
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

	rl := ratelimit.NewBackOff(&ratelimit.BackOffConfig{
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
	rlMw.Metrics = &prometheus.RateLimitMetricsListener{}

	handlerWithMiddleware := dnsserver.WithMiddlewares(
		dnsservertest.DefaultHandler(),
		rlMw,
	)

	// Pass 10 requests through the middleware.
	for i := 0; i < 10; i++ {
		req := dnsservertest.CreateMessage("example.org.", dns.TypeA)
		addr := &net.UDPAddr{IP: net.IP{1, 2, 3, 4}, Port: 53}
		nrw := dnsserver.NewNonWriterResponseWriter(addr, addr)
		ctx := dnsserver.ContextWithServerInfo(context.Background(), dnsserver.ServerInfo{
			Name:  "test",
			Addr:  "127.0.0.1",
			Proto: dnsserver.ProtoDNS,
		})
		ctx = dnsserver.ContextWithStartTime(ctx, time.Now())
		ctx = dnsserver.ContextWithClientInfo(ctx, dnsserver.ClientInfo{})

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
