package prometheus

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// RateLimitMetricsListener implements the [ratelimit.Metrics] interface
// and increments prom counters.
type RateLimitMetricsListener struct {
	dropCounters        *syncutil.OnceConstructor[reqLabelMetricKey, prometheus.Counter]
	allowlistedCounters *syncutil.OnceConstructor[reqLabelMetricKey, prometheus.Counter]
}

// NewRateLimitMetricsListener returns a new properly initialized
// *RateLimitMetricsListener.  As long as this function registers prometheus
// counters it must be called only once.
//
// TODO(a.garipov): Do not use promauto.
func NewRateLimitMetricsListener(namespace string) (l *RateLimitMetricsListener) {
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

	return &RateLimitMetricsListener{
		dropCounters: syncutil.NewOnceConstructor(
			func(k reqLabelMetricKey) (c prometheus.Counter) {
				return k.withLabelValues(droppedTotal)
			},
		),
		allowlistedCounters: syncutil.NewOnceConstructor(
			func(k reqLabelMetricKey) (c prometheus.Counter) {
				return k.withLabelValues(allowlistedTotal)
			},
		),
	}
}

// type check
var _ ratelimit.Metrics = (*RateLimitMetricsListener)(nil)

// OnRateLimited implements the [ratelimit.Metrics] interface for
// *RateLimitMetricsListener.
func (l *RateLimitMetricsListener) OnRateLimited(
	ctx context.Context,
	req *dns.Msg,
	rw dnsserver.ResponseWriter,
) {
	l.dropCounters.Get(newReqLabelMetricKey(ctx, req, rw)).Inc()
}

// OnAllowlisted implements the [ratelimit.Metrics] interface for
// *RateLimitMetricsListener.
func (l *RateLimitMetricsListener) OnAllowlisted(
	ctx context.Context,
	req *dns.Msg,
	rw dnsserver.ResponseWriter,
) {
	l.allowlistedCounters.Get(newReqLabelMetricKey(ctx, req, rw)).Inc()
}
