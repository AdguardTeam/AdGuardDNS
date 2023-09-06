package prometheus

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// RateLimitMetricsListener implements the [ratelimit.MetricsListener] interface
// and increments prom counters.
type RateLimitMetricsListener struct {
	dropCounters        *initSyncMap[reqLabelMetricKey, prometheus.Counter]
	allowlistedCounters *initSyncMap[reqLabelMetricKey, prometheus.Counter]
}

// NewRateLimitMetricsListener returns a new properly initialized
// *RateLimitMetricsListener.
func NewRateLimitMetricsListener() (l *RateLimitMetricsListener) {
	return &RateLimitMetricsListener{
		dropCounters: newInitSyncMap(func(k reqLabelMetricKey) (c prometheus.Counter) {
			return k.withLabelValues(droppedTotal)
		}),
		allowlistedCounters: newInitSyncMap(func(k reqLabelMetricKey) (c prometheus.Counter) {
			return k.withLabelValues(allowlistedTotal)
		}),
	}
}

// type check
var _ ratelimit.MetricsListener = (*RateLimitMetricsListener)(nil)

// OnRateLimited implements the ratelimit.MetricsListener interface for
// *RateLimitMetricsListener.
func (l *RateLimitMetricsListener) OnRateLimited(
	ctx context.Context,
	req *dns.Msg,
	rw dnsserver.ResponseWriter,
) {
	l.dropCounters.get(newReqLabelMetricKey(ctx, req, rw)).Inc()
}

// OnAllowlisted implements the ratelimit.MetricsListener interface for
// *RateLimitMetricsListener.
func (l *RateLimitMetricsListener) OnAllowlisted(
	ctx context.Context,
	req *dns.Msg,
	rw dnsserver.ResponseWriter,
) {
	l.allowlistedCounters.get(newReqLabelMetricKey(ctx, req, rw)).Inc()
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
