package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// FilterRulesTotal is a gauge with the number of rules loaded by each
	// filter.
	FilterRulesTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "rules_total",
		Subsystem: subsystemFilter,
		Namespace: namespace,
		Help:      "The number of rules loaded by filters.",
	}, []string{"filter"})

	// FilterUpdatedTime is a gauge with the last time when the filter was last
	// time updated.
	FilterUpdatedTime = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "updated_time",
		Subsystem: subsystemFilter,
		Namespace: namespace,
		Help:      "Time when the filter was last time updated.",
	}, []string{"filter"})

	// FilterUpdatedStatus is a gauge with status of the last filter update.
	// "0" means error, "1" means success.
	FilterUpdatedStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "update_status",
		Subsystem: subsystemFilter,
		Namespace: namespace,
		Help:      "Status of the filter update. 1 means success.",
	}, []string{"filter"})

	// filterCustomCacheLookups is a counter with the total number of lookups to
	// the custom filtering rules cache.  "hit" is "1" if the filter was found
	// in the cache, otherwise it is "0".
	filterCustomCacheLookups = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "custom_cache_lookups",
		Subsystem: subsystemFilter,
		Namespace: namespace,
		Help:      "Total number of custom filters cache lookups.",
	}, []string{"hit"})

	// FilterCustomCacheLookupsHits is a counter with the total number of the
	// custom filter cache hits.
	FilterCustomCacheLookupsHits = filterCustomCacheLookups.With(prometheus.Labels{"hit": "1"})

	// FilterCustomCacheLookupsMisses is a counter with the total number of the
	// custom filter cache misses.
	FilterCustomCacheLookupsMisses = filterCustomCacheLookups.With(prometheus.Labels{"hit": "0"})
)

var (
	// hashPrefixFilterCacheSize is a gauge with the total count of records in
	// the HashStorage cache.
	hashPrefixFilterCacheSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "hash_prefix_cache_size",
		Subsystem: subsystemFilter,
		Namespace: namespace,
		Help:      "The total number of items in the HashPrefixFilter cache.",
	}, []string{"filter"})

	// HashPrefixFilterSafeBrowsingCacheSize is the gauge with the total number
	// of items in the cache for domain names for safe browsing filter.
	HashPrefixFilterSafeBrowsingCacheSize = hashPrefixFilterCacheSize.With(prometheus.Labels{
		"filter": "safe_browsing",
	})

	// HashPrefixFilterAdultBlockingCacheSize is the gauge with the total number
	// of items in the cache for domain names for adult blocking filter.
	HashPrefixFilterAdultBlockingCacheSize = hashPrefixFilterCacheSize.With(prometheus.Labels{
		"filter": "adult_blocking",
	})

	// HashPrefixFilterNewRegDomainsCacheSize is the gauge with the total number
	// of items in the cache for domain names for safe browsing newly registered
	// domains filter.
	HashPrefixFilterNewRegDomainsCacheSize = hashPrefixFilterCacheSize.With(prometheus.Labels{
		"filter": "newly_registered_domains",
	})

	// hashPrefixFilterCacheLookups is a counter with the total number of host
	// cache lookups.  "hit" is either "1" (item found) or "0". (item not found).
	hashPrefixFilterCacheLookups = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "hash_prefix_cache_lookups",
		Subsystem: subsystemFilter,
		Namespace: namespace,
		Help: "The number of HashPrefixFilter host cache lookups. " +
			"hit=1 means that a cached item was found.",
	}, []string{"hit", "filter"})

	// HashPrefixFilterCacheSafeBrowsingHits is a counter with the total number
	// of safe browsing filter cache hits.
	HashPrefixFilterCacheSafeBrowsingHits = hashPrefixFilterCacheLookups.With(prometheus.Labels{
		"hit":    "1",
		"filter": "safe_browsing",
	})

	// HashPrefixFilterCacheSafeBrowsingMisses is a counter with the total number
	// of safe browsing filter cache misses.
	HashPrefixFilterCacheSafeBrowsingMisses = hashPrefixFilterCacheLookups.With(prometheus.Labels{
		"hit":    "0",
		"filter": "safe_browsing",
	})

	// HashPrefixFilterCacheAdultBlockingHits is a counter with the total number
	// of adult blocking filter cache hits.
	HashPrefixFilterCacheAdultBlockingHits = hashPrefixFilterCacheLookups.With(prometheus.Labels{
		"hit":    "1",
		"filter": "adult_blocking",
	})

	// HashPrefixFilterCacheAdultBlockingMisses is a counter with the total number
	// of adult blocking filter cache misses.
	HashPrefixFilterCacheAdultBlockingMisses = hashPrefixFilterCacheLookups.With(prometheus.Labels{
		"hit":    "0",
		"filter": "adult_blocking",
	})

	// HashPrefixFilterCacheNewRegDomainsHits is a counter with the total number
	// of newly registered domains filter cache hits.
	HashPrefixFilterCacheNewRegDomainsHits = hashPrefixFilterCacheLookups.With(prometheus.Labels{
		"hit":    "1",
		"filter": "newly_registered_domains",
	})

	// HashPrefixFilterCacheNewRegDomainsMisses is a counter with the total
	// number of newly registered domains filter cache misses.
	HashPrefixFilterCacheNewRegDomainsMisses = hashPrefixFilterCacheLookups.With(prometheus.Labels{
		"hit":    "0",
		"filter": "newly_registered_domains",
	})
)
