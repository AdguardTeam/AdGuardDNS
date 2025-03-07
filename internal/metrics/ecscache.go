package metrics

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// ECSCache is a Prometheus-based implementation of the [ecscache.Metrics]
// interface.
type ECSCache struct {
	// supportedCount is a gauge with the total number of items in the cache for
	// domain names that support ECS.
	supportedCount prometheus.Gauge

	// unsupportedCount is a gauge with the total number of items in the cache
	// for domain names that do not support ECS.
	unsupportedCount prometheus.Gauge

	// hitsTotal is a counter with the total number of ECS cache hits.
	hitsTotal prometheus.Counter

	// missesTotal is a counter with the total number of ECS cache misses.
	missesTotal prometheus.Counter

	// supportedHitsTotal is a counter with the total number of ECS cache hits
	// for hosts that support ECS.
	supportedHitsTotal prometheus.Counter

	// supportedMissesTotal is a counter with the total number of ECS cache
	// misses for hosts that support ECS.
	supportedMissesTotal prometheus.Counter

	// unsupportedHitsTotal is a counter with the total number of ECS cache hits
	// for hosts that don't support ECS.
	unsupportedHitsTotal prometheus.Counter

	// unsupportedMissesTotal is a counter with the total number of ECS cache
	// misses for hosts that don't support ECS.
	unsupportedMissesTotal prometheus.Counter
}

// NewECSCache registers the ECS cache metrics in reg and returns a properly
// initialized [*ECSCache].
func NewECSCache(namespace string, reg prometheus.Registerer) (m *ECSCache, err error) {
	const (
		size             = "size"
		cacheLookupTotal = "total_cache_lookups"
	)

	ecsCacheSize := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:      size,
		Namespace: namespace,
		Subsystem: subsystemECSCache,
		Help:      "The total number of items in the ECS cache.",
	}, []string{"supports"})
	ecsCacheLookups := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      cacheLookupTotal,
		Subsystem: subsystemECSCache,
		Namespace: namespace,
		Help: "The total number of ECS cache lookups. hit=1 means that a " +
			"cached item was found.",
	}, []string{"supports", "hit"})

	m = &ECSCache{
		supportedCount:   ecsCacheSize.WithLabelValues("yes"),
		unsupportedCount: ecsCacheSize.WithLabelValues("no"),

		hitsTotal:   ecsCacheLookups.WithLabelValues("all", "1"),
		missesTotal: ecsCacheLookups.WithLabelValues("all", "0"),

		supportedHitsTotal:   ecsCacheLookups.WithLabelValues("yes", "1"),
		supportedMissesTotal: ecsCacheLookups.WithLabelValues("yes", "0"),

		unsupportedHitsTotal:   ecsCacheLookups.WithLabelValues("no", "1"),
		unsupportedMissesTotal: ecsCacheLookups.WithLabelValues("no", "0"),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   size,
		Value: ecsCacheSize,
	}, {
		Key:   cacheLookupTotal,
		Value: ecsCacheLookups,
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

	return m, nil
}

// SetElementsCount implements the [ecscache.Metrics] interface for *ECSCache.
func (m *ECSCache) SetElementsCount(_ context.Context, supportsECS bool, count int) {
	if supportsECS {
		m.supportedCount.Set(float64(count))
	} else {
		m.unsupportedCount.Set(float64(count))
	}
}

// IncrementLookups implements the [ecscache.Metrics] interface for *ECSCache.
func (m *ECSCache) IncrementLookups(_ context.Context, supportsECS, hit bool) {
	IncrementCond(hit, m.hitsTotal, m.missesTotal)
	if hit {
		IncrementCond(supportsECS, m.supportedHitsTotal, m.unsupportedHitsTotal)
	} else {
		IncrementCond(supportsECS, m.supportedMissesTotal, m.unsupportedMissesTotal)
	}
}
