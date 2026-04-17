package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// BackendFilterIndexStorage is a metrics collector for filter-index storages.
type BackendFilterIndexStorage struct {
	// typosquattingErrorsTotal is the counter with the total number of errors
	// occurred during filter-index updates.
	typosquattingErrorsTotal prometheus.Counter

	// typosquattingUpdateDuration is the histogram with the duration of the
	// last filter-index update.
	typosquattingUpdateDuration prometheus.Observer
}

// NewBackendFilterIndexStorage returns a new *BackendFilterIndexStorage that
// collects metrics about filter-index updates.
func NewBackendFilterIndexStorage(
	namespace string,
	reg prometheus.Registerer,
) (m *BackendFilterIndexStorage, err error) {
	const (
		errorsTotal    = "filter_index_storage_update_errors_total"
		updateDuration = "filter_index_storage_update_duration"
	)

	var (
		errorsTotalCounters = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      errorsTotal,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help: "The total number of errors occurred during filter-index updates, " +
				"by method.",
		}, []string{"method"})

		updateDurationHistograms = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:      updateDuration,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "Duration of the filter-index storage update in seconds, by method.",
			Buckets:   []float64{0.001, 0.01, 0.1, 1},
		}, []string{"method"})
	)

	m = &BackendFilterIndexStorage{
		typosquattingErrorsTotal:    errorsTotalCounters.WithLabelValues("typosquatting"),
		typosquattingUpdateDuration: updateDurationHistograms.WithLabelValues("typosquatting"),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   errorsTotal,
		Value: errorsTotalCounters,
	}, {
		Key:   updateDuration,
		Value: updateDurationHistograms,
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

// ObserveTyposquatting implements the [backendgrpc.FilterIndexStorageMetrics]
// interface for *BackendFilterIndexStorage.
func (m *BackendFilterIndexStorage) ObserveTyposquatting(
	_ context.Context,
	d time.Duration,
	err error,
) {
	m.typosquattingUpdateDuration.Observe(d.Seconds())
	if err != nil {
		m.typosquattingErrorsTotal.Inc()
	}
}
