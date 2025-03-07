package prometheus

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
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
// TODO(s.chzhen):  Use it.
func NewRateLimitMetricsListener(
	namespace string,
	reg prometheus.Registerer,
) (l *RateLimitMetricsListener, err error) {
	const (
		droppedTotalMtrcName     = "dropped_total"
		allowlistedTotalMtrcName = "allowlisted_total"
	)

	var (
		droppedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      droppedTotalMtrcName,
			Namespace: namespace,
			Subsystem: subsystemRateLimit,
			Help:      "The total number of rate-limited DNS queries.",
		}, []string{"name", "proto", "network", "addr", "type", "family"})

		allowlistedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      allowlistedTotalMtrcName,
			Namespace: namespace,
			Subsystem: subsystemRateLimit,
			Help:      "The total number of allowlisted DNS queries.",
		}, []string{"name", "proto", "network", "addr", "type", "family"})
	)

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   droppedTotalMtrcName,
		Value: droppedTotal,
	}, {
		Key:   allowlistedTotalMtrcName,
		Value: allowlistedTotal,
	}}

	for _, c := range collectors {
		err = reg.Register(c.Value)
		if err != nil {
			errs = append(errs, fmt.Errorf("registering metrics %q: %w", c.Key, err))
		}
	}

	if err = errors.Join(errs...); err != nil {
		return nil, err
	}

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
	}, nil
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
