package prometheus

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/cache"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

// cacheTypeDefault is a "type" label value for the default LRU cache.  In the
// future, a separate ECS cache may appear.
const cacheTypeDefault = "default"

// CacheMetricsListener implements the cache.MetricsListener interface and
// increments Prometheus counters.
type CacheMetricsListener struct {
	cacheSize   *prometheus.GaugeVec
	hitsTotal   *prometheus.CounterVec
	missesTotal *prometheus.CounterVec
}

// NewCacheMetricsListener returns a new properly initialized
// *CacheMetricsListener.  As long as this function registers prometheus
// counters it must be called only once.
func NewCacheMetricsListener(
	namespace string,
	reg prometheus.Registerer,
) (l *CacheMetricsListener, err error) {
	const (
		cacheSize   = "size"
		hitsTotal   = "hits_total"
		missesTotal = "misses_total"
	)

	l = &CacheMetricsListener{
		cacheSize: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      cacheSize,
			Namespace: namespace,
			Subsystem: subsystemCache,
			Help:      "The total number items in the cache.",
		}, []string{"type"}),

		hitsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      hitsTotal,
			Namespace: namespace,
			Subsystem: subsystemCache,
			Help:      "The total number of cache hits.",
		}, []string{"type"}),

		missesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      missesTotal,
			Namespace: namespace,
			Subsystem: subsystemCache,
			Help:      "The total number of cache misses.",
		}, []string{"type"}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   cacheSize,
		Value: l.cacheSize,
	}, {
		Key:   hitsTotal,
		Value: l.hitsTotal,
	}, {
		Key:   missesTotal,
		Value: l.missesTotal,
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

	return l, nil
}

// type check
var _ cache.MetricsListener = (*CacheMetricsListener)(nil)

// OnCacheItemAdded implements the [cache.MetricsListener] interface for
// *CacheMetricsListener.
func (c *CacheMetricsListener) OnCacheItemAdded(_ context.Context, _ *dns.Msg, cacheLen int) {
	c.cacheSize.WithLabelValues(cacheTypeDefault).Set(float64(cacheLen))
}

// OnCacheHit implements the [cache.MetricsListener] interface for
// *CacheMetricsListener.
func (c *CacheMetricsListener) OnCacheHit(_ context.Context, _ *dns.Msg) {
	c.hitsTotal.WithLabelValues(cacheTypeDefault).Inc()
}

// OnCacheMiss implements the [cache.MetricsListener] interface for
// *CacheMetricsListener.
func (c *CacheMetricsListener) OnCacheMiss(_ context.Context, _ *dns.Msg) {
	c.missesTotal.WithLabelValues(cacheTypeDefault).Inc()
}
