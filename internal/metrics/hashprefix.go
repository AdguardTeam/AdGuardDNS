package metrics

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// HashPrefixFilter is the Prometheus-based implementation of the
// [hashprefix.Metrics] interface.
type HashPrefixFilter struct {
	// cacheSize is a gauge with the total count of records in the HashStorage
	// cache.
	cacheSize prometheus.Gauge

	// hits is a counter of the total number of lookups to the HashStorage
	// cache that succeeded.
	hits prometheus.Counter

	// misses is a counter of the total number of lookups to the HashStorage
	// cache that resulted in a miss.
	misses prometheus.Counter
}

// NewHashPrefixFilter registers the filtering metrics in reg and returns a
// properly initialized *HashPrefixFilter.  filterName must be a valid label
// name.
func NewHashPrefixFilter(
	namespace string,
	filterName string,
	reg prometheus.Registerer,
) (m *HashPrefixFilter, err error) {
	const (
		cacheLookups = "hash_prefix_cache_lookups"
		cacheSize    = "hash_prefix_cache_size"
	)

	labels := prometheus.Labels{"filter": filterName}

	lookups := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      cacheLookups,
		Subsystem: subsystemFilter,
		Namespace: namespace,
		Help: "Total number of lookups to HashPrefixFilter host cache lookups. " +
			"Label hit is the lookup result, either 1 for hit or 0 for miss.",
		ConstLabels: labels,
	}, []string{"hit"})

	m = &HashPrefixFilter{
		cacheSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        cacheSize,
			Subsystem:   subsystemFilter,
			Namespace:   namespace,
			Help:        "The total number of items in the HashPrefixFilter cache.",
			ConstLabels: labels,
		}),
		hits:   lookups.WithLabelValues("1"),
		misses: lookups.WithLabelValues("0"),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   cacheSize,
		Value: m.cacheSize,
	}, {
		Key:   cacheLookups,
		Value: lookups,
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

// IncrementLookups implements the [hashprefix.Metrics] interface for
// *HashPrefixFilter.
func (m *HashPrefixFilter) IncrementLookups(_ context.Context, hit bool) {
	IncrementCond(hit, m.hits, m.misses)
}

// UpdateCacheSize implements the [hashprefix.Metrics] interface for
// *HashPrefixFilter.
func (m *HashPrefixFilter) UpdateCacheSize(_ context.Context, size int) {
	m.cacheSize.Set(float64(size))
}
