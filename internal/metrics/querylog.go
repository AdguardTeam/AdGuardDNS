package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/c2h5oh/datasize"
	"github.com/prometheus/client_golang/prometheus"
)

// QueryLog is the Prometheus-based implementation of the [querylog.Metrics]
// interface.
type QueryLog struct {
	itemsTotal    prometheus.Counter
	itemSize      prometheus.Histogram
	writeDuration prometheus.Histogram
}

// NewQueryLog creates a new Prometheus-based query log metrics collector.
func NewQueryLog(namespace string, reg prometheus.Registerer) (m *QueryLog, err error) {
	const (
		itemsTotal    = "items_total"
		itemSize      = "items_size_bytes"
		writeDuration = "write_duration_seconds"
	)

	m = &QueryLog{
		itemsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:      itemsTotal,
			Subsystem: subsystemQueryLog,
			Namespace: namespace,
			Help:      "The total number of query log items written.",
		}),
		itemSize: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:      itemSize,
			Subsystem: subsystemQueryLog,
			Namespace: namespace,
			Help:      "A histogram with the query log items size.",
			// Query log items are measured in bytes. Most of the space might be
			// taken by domain names and filtering rules which might in theory
			// be pretty long, therefore buckets are up to 2000 bytes.
			Buckets: []float64{50, 100, 200, 300, 400, 600, 800, 1000, 2000},
		}),
		writeDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:      writeDuration,
			Subsystem: subsystemQueryLog,
			Namespace: namespace,
			Help:      "A histogram with the query log items size.",
			// We chose buckets considering that writing to a file is a fast
			// operation.  If for some reason it takes over 1ms, something went
			// terribly wrong.
			Buckets: []float64{0.00001, 0.0001, 0.001, 0.01, 0.1, 1},
		}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   itemsTotal,
		Value: m.itemsTotal,
	}, {
		Key:   itemSize,
		Value: m.itemSize,
	}, {
		Key:   writeDuration,
		Value: m.writeDuration,
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

// type check
var _ querylog.Metrics = (*QueryLog)(nil)

// ObserveItemSize implements the [querylog.Metrics] interface for *QueryLog.
func (m *QueryLog) ObserveItemSize(_ context.Context, size datasize.ByteSize) {
	m.itemSize.Observe(float64(size))
}

// ObserveWrite implements the [querylog.Metrics] interface for
// *QueryLog.
func (m *QueryLog) ObserveWrite(_ context.Context, dur time.Duration) {
	m.itemsTotal.Inc()
	m.writeDuration.Observe(dur.Seconds())
}
