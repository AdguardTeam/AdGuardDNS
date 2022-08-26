package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Cache size metrics.
var (
	// ecsCacheSize is the gauge with the total number of items in a cache.
	// "supports" is either "yes" (the metric is for hostnames that support ECS)
	// or "no" (the metric is for hostnames that don't support ECS).
	ecsCacheSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "size",
		Namespace: namespace,
		Subsystem: subsystemECSCache,
		Help:      "The total number of items in the ECS cache.",
	}, []string{"supports"})

	// ECSNoSupportCacheSize is the gauge with the total number of items in
	// the cache for domain names that do not support ECS.
	ECSNoSupportCacheSize = ecsCacheSize.With(prometheus.Labels{
		"supports": "no",
	})

	// ECSHasSupportCacheSize is the gauge with the total number of items in
	// the cache for domain names that support ECS.
	ECSHasSupportCacheSize = ecsCacheSize.With(prometheus.Labels{
		"supports": "yes",
	})
)

// Lookup metrics.
var (
	// ecsCacheLookups is a counter with the total number of the ECS cache
	// lookups.  "hit" is either "1" (item found) or "0" (item not found).
	// "supports" is either "yes" (the metric is for hostnames that support
	// ECS), "no" (the metric is for hostnames that don't support ECS), or "all"
	// (the metric is for all hosts).
	ecsCacheLookups = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "total_cache_lookups",
		Subsystem: subsystemECSCache,
		Namespace: namespace,
		Help: "The total number of ECS cache lookups. " +
			"hit=1 means that a cached item was found.",
	}, []string{"supports", "hit"})

	// ECSCacheLookupTotalHits is a counter with the total number of ECS cache
	// hits.
	ECSCacheLookupTotalHits = ecsCacheLookups.With(prometheus.Labels{
		"hit":      "1",
		"supports": "all",
	})

	// ECSCacheLookupHasSupportHits is a counter with the number of ECS cache
	// hits for hosts that support ECS.
	ECSCacheLookupHasSupportHits = ecsCacheLookups.With(prometheus.Labels{
		"hit":      "1",
		"supports": "yes",
	})

	// ECSCacheLookupNoSupportHits is a counter with the number of ECS cache
	// hits for hosts that don't support ECS.
	ECSCacheLookupNoSupportHits = ecsCacheLookups.With(prometheus.Labels{
		"hit":      "1",
		"supports": "no",
	})

	// ECSCacheLookupTotalMisses is a counter with the total number of ECS cache
	// misses.
	ECSCacheLookupTotalMisses = ecsCacheLookups.With(prometheus.Labels{
		"hit":      "0",
		"supports": "all",
	})

	// ECSCacheLookupHasSupportMisses is a counter with the number of ECS cache
	// misses for hosts that support ECS.
	ECSCacheLookupHasSupportMisses = ecsCacheLookups.With(prometheus.Labels{
		"hit":      "0",
		"supports": "yes",
	})

	// ECSCacheLookupNoSupportMisses is a counter with the number of ECS cache
	// misses for hosts that don't support ECS.
	ECSCacheLookupNoSupportMisses = ecsCacheLookups.With(prometheus.Labels{
		"hit":      "0",
		"supports": "no",
	})
)
