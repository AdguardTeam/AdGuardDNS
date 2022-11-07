package prometheus

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// RateLimitMetricsListener implements the ratelimit.MetricsListener interface
// and increments prom counters.
type RateLimitMetricsListener struct{}

// type check
var _ ratelimit.MetricsListener = (*RateLimitMetricsListener)(nil)

// OnRateLimited implements the ratelimit.MetricsListener interface for
// *RateLimitMetricsListener.
func (r *RateLimitMetricsListener) OnRateLimited(
	ctx context.Context,
	req *dns.Msg,
	rw dnsserver.ResponseWriter,
) {
	reqLabels := requestLabels(ctx, req, rw)
	droppedTotal.With(reqLabels).Inc()
}

// OnAllowlisted implements the ratelimit.MetricsListener interface for
// *RateLimitMetricsListener.
func (r *RateLimitMetricsListener) OnAllowlisted(
	ctx context.Context,
	req *dns.Msg,
	rw dnsserver.ResponseWriter,
) {
	reqLabels := requestLabels(ctx, req, rw)
	allowlistedTotal.With(reqLabels).Inc()
}

// This block contains prometheus metrics declarations for ratelimit.Middleware
var (
	droppedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "dropped_total",
		Namespace: namespace,
		Subsystem: subsystemRateLimit,
		Help:      "The total number of rate-limited DNS queries.",
	}, []string{"name", "proto", "network", "addr", "type", "family"})

	allowlistedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "allowlisted_total",
		Namespace: namespace,
		Subsystem: subsystemRateLimit,
		Help:      "The total number of allowlisted DNS queries.",
	}, []string{"name", "proto", "network", "addr", "type", "family"})
)
