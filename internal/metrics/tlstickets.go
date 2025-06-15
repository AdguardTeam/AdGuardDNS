package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// BackendTicketStorage is a metrics collector for TLS session ticket updates.
type BackendTicketStorage struct {
	// updateStatus is the gauge vector with status of the last TLS session
	// ticket update.  "0" means error, "1" means success.
	updateStatus *prometheus.GaugeVec

	// updateTime is the gauge vector with the last time when the TLS session
	// ticket was last updated.
	updatedTime *prometheus.GaugeVec

	// updateDuration is the histogram with the duration of the last TLS session
	// tickets update.
	updateDuration prometheus.Histogram

	// errorsTotal is the counter with the total number of errors occurred
	// during TLS session ticket updates.
	errorsTotal prometheus.Counter
}

// NewBackendTicketStorage returns a new BackendTicketStorage that collects
// metrics about TLS session ticket updates.
func NewBackendTicketStorage(
	namespace string,
	reg prometheus.Registerer,
) (m *BackendTicketStorage, err error) {
	const (
		updateStatus   = "update_status"
		updatedTime    = "update_time"
		updateDuration = "update_duration"
		errorsTotal    = "update_errors_total"
	)

	m = &BackendTicketStorage{
		updateStatus: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      updateStatus,
			Subsystem: subsystemTLS,
			Namespace: namespace,
			Help:      "Status of the TLS session ticket update. 1 means success.",
		}, []string{"name"}),
		updatedTime: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      updatedTime,
			Subsystem: subsystemTLS,
			Namespace: namespace,
			Help:      "Time when the TLS session ticket was last time updated.",
		}, []string{"name"}),
		updateDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:      "update_duration_seconds",
			Subsystem: subsystemTLS,
			Namespace: namespace,
			Help:      "Duration of the last TLS session ticket update in seconds.",
			Buckets:   []float64{0.001, 0.01, 0.1, 1},
		}),
		errorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:      "update_errors_total",
			Subsystem: subsystemTLS,
			Namespace: namespace,
			Help:      "The total number of errors occurred during TLS session ticket updates.",
		}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   updateStatus,
		Value: m.updateStatus,
	}, {
		Key:   updatedTime,
		Value: m.updatedTime,
	}, {
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

// SetTicketStatus implements the [backendpb.TicketStorageMetrics] interface for
// *BackendTicketStorage.
func (m *BackendTicketStorage) SetTicketStatus(
	ctx context.Context,
	name string,
	updTime time.Time,
	err error,
) {
	if err != nil {
		m.updateStatus.WithLabelValues(name).Set(0)

		return
	}

	m.updateStatus.WithLabelValues(name).Set(1)
	m.updatedTime.WithLabelValues(name).Set(float64(updTime.Unix()))
}

// ObserveUpdate implements the [backendpb.TicketStorageMetrics] interface for
// *BackendTicketStorage.
func (m *BackendTicketStorage) ObserveUpdate(_ context.Context, d time.Duration, err error) {
	m.updateDuration.Observe(d.Seconds())
	if err != nil {
		m.errorsTotal.Inc()
	}
}
