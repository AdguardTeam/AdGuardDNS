package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// DNSDB is the Prometheus-based implementation of the [dnsdb.Metrics]
// interface.
type DNSDB struct {
	// recordCount is a gauge with the total count of records in the in-memory
	// temporary buffer.
	recordCount prometheus.Gauge

	// rotateTime is a gauge with the time at which the DNS database was
	// rotated.
	rotateTime prometheus.Gauge

	// rotateDuration is a histogram that stores the time elapsed during the
	// rotation of the DNS database.
	rotateDuration prometheus.Histogram
}

// NewDNSDB registers the filtering rule metrics in reg and returns a properly
// initialized [*DNSDB].
func NewDNSDB(namespace string, reg prometheus.Registerer) (m *DNSDB, err error) {
	const (
		recordCount    = "buffer_size"
		rotateTime     = "rotate_time"
		rotateDuration = "save_duration"
	)

	m = &DNSDB{
		recordCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      recordCount,
			Namespace: namespace,
			Subsystem: subsystemDNSDB,
			Help:      "Count of records in the in-memory buffer.",
		}),
		rotateTime: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      rotateTime,
			Namespace: namespace,
			Subsystem: subsystemDNSDB,
			Help:      "Last time when the database was rotated.",
		}),
		rotateDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:      rotateDuration,
			Namespace: namespace,
			Subsystem: subsystemDNSDB,
			Help:      "Time elapsed on rotating the buffer for sending over HTTP.",
		}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   recordCount,
		Value: m.recordCount,
	}, {
		Key:   rotateTime,
		Value: m.rotateTime,
	}, {
		Key:   rotateDuration,
		Value: m.rotateDuration,
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

// SetRecordCount implements the [dnsdb.Metrics] interface for *DNSDB.
func (m *DNSDB) SetRecordCount(_ context.Context, count int) {
	m.recordCount.Set(float64(count))
}

// ObserveRotation implements the [dnsdb.Metrics] interface for *DNSDB.
func (m *DNSDB) ObserveRotation(_ context.Context, dur time.Duration) {
	m.rotateTime.SetToCurrentTime()
	m.rotateDuration.Observe(dur.Seconds())
}
