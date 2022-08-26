package prometheus

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/cache"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// defaultCacheType is a "type" label value for the default LRU cache.
// In the future there might be a separate ECS cache.
const defaultCacheType = "default"

// CacheMetricsListener implements the cache.MetricsListener interface
// and increments prom counters.
type CacheMetricsListener struct{}

// type check
var _ cache.MetricsListener = (*CacheMetricsListener)(nil)

// OnCacheItemAdded implements the cache.MetricsListener interface for
// *CacheMetricsListener.
func (c *CacheMetricsListener) OnCacheItemAdded(_ context.Context, _ *dns.Msg, cacheLen int) {
	cacheSize.WithLabelValues(defaultCacheType).Set(float64(cacheLen))
}

// OnCacheHit implements the cache.MetricsListener interface for
// *CacheMetricsListener.
func (c *CacheMetricsListener) OnCacheHit(_ context.Context, _ *dns.Msg) {
	cacheHitsTotal.WithLabelValues(defaultCacheType).Inc()
}

// OnCacheMiss implements the cache.MetricsListener interface for
// *CacheMetricsListener.
func (c *CacheMetricsListener) OnCacheMiss(_ context.Context, _ *dns.Msg) {
	cacheMissesTotal.WithLabelValues(defaultCacheType).Inc()
}

// This block contains prometheus metrics declarations for cache.Middleware.
var (
	cacheSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "size",
		Namespace: namespace,
		Subsystem: subsystemCache,
		Help:      "The total number items in the cache.",
	}, []string{"type"})

	cacheHitsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "hits_total",
		Namespace: namespace,
		Subsystem: subsystemCache,
		Help:      "The total number of cache hits.",
	}, []string{"type"})

	cacheMissesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "misses_total",
		Namespace: namespace,
		Subsystem: subsystemCache,
		Help:      "The total number of cache misses.",
	}, []string{"type"})
)
