package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// BackendCustomDomainStorage is the Prometheus-based implementation of the
// [backendpb.CustomDomainStorageMetrics] interface.
//
// TODO(a.garipov):  Use.
type BackendCustomDomainStorage struct {
	// errorsTotal is a counter of the total number of errors when requesting
	// certificate data.
	errorsTotal prometheus.Counter

	// requestDuration is a histogram with the duration of a receive of a single
	// piece of certificate data from the backend certificate-data storage.
	requestDuration prometheus.Histogram

	// requestsTotal is a counter of the total number of requests for
	// certificate data.
	requestsTotal prometheus.Counter
}

// NewBackendCustomDomainStorage registers the backend custom-domain data
// storage metrics in reg and returns a properly initialized
// [BackendCustomDomainStorage].
func NewBackendCustomDomainStorage(
	namespace string,
	reg prometheus.Registerer,
) (m *BackendCustomDomainStorage, err error) {
	const (
		errorsTotal     = "grpc_custom_domain_storage_errors_total"
		requestDuration = "grpc_custom_domain_storage_request_duration"
		requestsTotal   = "grpc_custom_domain_storage_requests_total"
	)

	m = &BackendCustomDomainStorage{
		errorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:      errorsTotal,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "Total number of errors when requesting certificate data.",
		}),
		requestDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:      requestDuration,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "Duration of a receive of a single piece of certificate data, in seconds.",
			Buckets:   []float64{0.001, 0.01, 0.1, 1},
		}),
		requestsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:      requestsTotal,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "Total number of requests for certificate data.",
		}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   errorsTotal,
		Value: m.errorsTotal,
	}, {
		Key:   requestDuration,
		Value: m.requestDuration,
	}, {
		Key:   requestsTotal,
		Value: m.requestsTotal,
	}}

	for _, c := range collectors {
		err = reg.Register(c.Value)
		if err != nil {
			errs = append(errs, fmt.Errorf("registering metrics: %q: %w", c.Key, err))
		}
	}

	if err = errors.Join(errs...); err != nil {
		return nil, err
	}

	return m, nil
}

// ObserveRequest implements the [backendpb.CustomDomainStorageMetrics]
// interface for *BackendCustomDomainStorage.
func (m *BackendCustomDomainStorage) ObserveRequest(_ context.Context, dur time.Duration, err error) {
	m.requestsTotal.Inc()
	if err == nil {
		m.requestDuration.Observe(float64(dur))
	} else {
		m.errorsTotal.Inc()
	}
}
