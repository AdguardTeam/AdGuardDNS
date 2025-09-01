package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// BackendStandardAccess is a metrics collector for standard access updates.
type BackendStandardAccess struct {
	// updateDuration is the histogram with the duration of the last TLS session
	// tickets update.
	updateDuration prometheus.Histogram

	// errorsTotal is the counter with the total number of errors occurred
	// during TLS session ticket updates.
	errorsTotal prometheus.Counter
}

// NewBackendStandardAccess returns a new StandardAccessStorage that collects
// metrics about standard access updates.
func NewBackendStandardAccess(
	namespace string,
	reg prometheus.Registerer,
) (m *BackendStandardAccess, err error) {
	const (
		updateDuration = "standard_access_update_duration"
		errorsTotal    = "standard_access_update_errors_total"
	)

	m = &BackendStandardAccess{
		updateDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:      updateDuration,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "Duration of the last standard access update in seconds.",
			Buckets:   []float64{0.001, 0.01, 0.1, 1},
		}),
		errorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:      errorsTotal,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "The total number of errors occurred during standard access updates.",
		}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   updateDuration,
		Value: m.updateDuration,
	}, {
		Key:   errorsTotal,
		Value: m.errorsTotal,
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

// ObserveUpdate implements the [backendpb.StandardAccessMetrics] interface for
// *BackendStandardAccess.
func (m *BackendStandardAccess) ObserveUpdate(_ context.Context, d time.Duration, err error) {
	m.updateDuration.Observe(d.Seconds())
	if err != nil {
		m.errorsTotal.Inc()
	}
}
