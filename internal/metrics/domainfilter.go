package metrics

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// DomainFilter is the Prometheus-based implementation of the
// [domain.Metrics] interface.
type DomainFilter struct {
	// cacheSize is a gauge with the total count of records in the DomainStorage
	// cache.
	cacheSize *prometheus.GaugeVec

	// lookups is a counter of the total number of lookups to the DomainStorage
	// cache.
	lookups *prometheus.CounterVec
}

// NewDomainFilter registers the filtering metrics in reg and returns a properly
// initialized *DomainFilter.
func NewDomainFilter(namespace string, reg prometheus.Registerer) (m *DomainFilter, err error) {
	const (
		cacheLookups = "domain_filter_cache_lookups"
		cacheSize    = "domain_filter_cache_size"
	)

	m = &DomainFilter{
		cacheSize: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      cacheSize,
			Subsystem: subsystemFilter,
			Namespace: namespace,
			Help:      "The total number of items in the DomainFilter cache.",
		}, []string{"category"}),
		lookups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      cacheLookups,
			Subsystem: subsystemFilter,
			Namespace: namespace,
			Help: "Total number of lookups to DomainFilter host cache lookups. " +
				"Label hit is the lookup result, either 1 for hit or 0 for miss.",
		}, []string{"category", "hit"}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   cacheSize,
		Value: m.cacheSize,
	}, {
		Key:   cacheLookups,
		Value: m.lookups,
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

// IncrementLookups implements the [domain.Metrics] interface for *DomainFilter.
func (m *DomainFilter) IncrementLookups(_ context.Context, categoryID filter.CategoryID, hit bool) {
	catIDStr := string(categoryID)

	if hit {
		m.lookups.WithLabelValues(catIDStr, "1").Inc()
	} else {
		m.lookups.WithLabelValues(catIDStr, "0").Inc()
	}
}

// UpdateCacheSize implements the [domain.Metrics] interface for *DomainFilter.
func (m *DomainFilter) UpdateCacheSize(_ context.Context, categoryID filter.CategoryID, size int) {
	m.cacheSize.WithLabelValues(string(categoryID)).Set(float64(size))
}
