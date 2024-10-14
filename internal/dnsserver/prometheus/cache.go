package prometheus

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/cache"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
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
//
// TODO(a.garipov): Do not use promauto.
func NewCacheMetricsListener(namespace string) *CacheMetricsListener {
	return &CacheMetricsListener{
		cacheSize: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name:      "size",
			Namespace: namespace,
			Subsystem: subsystemCache,
			Help:      "The total number items in the cache.",
		}, []string{"type"}),

		hitsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name:      "hits_total",
			Namespace: namespace,
			Subsystem: subsystemCache,
			Help:      "The total number of cache hits.",
		}, []string{"type"}),

		missesTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name:      "misses_total",
			Namespace: namespace,
			Subsystem: subsystemCache,
			Help:      "The total number of cache misses.",
		}, []string{"type"}),
	}
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
