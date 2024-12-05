package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
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

// Filter is the Prometheus-based implementation of the [Filter]
// interface.
type Filter struct {
	// rulesTotal is the gauge vector with the number of rules loaded by each
	// filter.
	rulesTotal *prometheus.GaugeVec

	// updateStatus is the gauge vector with status of the last filter update.
	// "0" means error, "1" means success.
	updateStatus *prometheus.GaugeVec

	// updateTime is the gauge vector with the last time when the filter was
	// last updated.
	updatedTime *prometheus.GaugeVec
}

// NewFilter registers the filtering metrics in reg and returns a properly
// initialized *Filter.
func NewFilter(namespace string, reg prometheus.Registerer) (m *Filter, err error) {
	const (
		rulesTotal   = "rules_total"
		updateStatus = "update_status"
		updatedTime  = "updated_time"
	)

	m = &Filter{
		rulesTotal: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      rulesTotal,
			Subsystem: subsystemFilter,
			Namespace: namespace,
			Help:      "The number of rules loaded by filters.",
		}, []string{"filter"}),

		updateStatus: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      updateStatus,
			Subsystem: subsystemFilter,
			Namespace: namespace,
			Help:      "Status of the filter update. 1 means success.",
		}, []string{"filter"}),

		updatedTime: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      updatedTime,
			Subsystem: subsystemFilter,
			Namespace: namespace,
			Help:      "Time when the filter was last time updated.",
		}, []string{"filter"}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   rulesTotal,
		Value: m.rulesTotal,
	}, {
		Key:   updateStatus,
		Value: m.updateStatus,
	}, {
		Key:   updatedTime,
		Value: m.updatedTime,
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

// SetFilterStatus implements the [filter.Metrics] interface for *Filter.
func (m *Filter) SetFilterStatus(
	ctx context.Context,
	id string,
	updTime time.Time,
	ruleCount int,
	err error,
) {
	if err != nil {
		m.updateStatus.WithLabelValues(id).Set(0)

		return
	}

	m.rulesTotal.WithLabelValues(id).Set(float64(ruleCount))
	m.updateStatus.WithLabelValues(id).Set(1)
	m.updatedTime.WithLabelValues(id).Set(float64(updTime.UnixNano()) / float64(time.Second))
}
