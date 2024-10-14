package metrics

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// Billstat is the Prometheus-based implementation of the [billstat.Metrics]
// interface.
type Billstat struct {
	// bufSize is a gauge with the total count of records in the local billing
	// statistics database.
	bufSize prometheus.Gauge

	// uploadStatus is a gauge with the status of the last billing statistics
	// upload.
	uploadStatus prometheus.Gauge

	// uploadTimestamp is a gauge with the timestamp of the last billing
	// statistics upload.
	uploadTimestamp prometheus.Gauge

	// uploadDuration is a histogram with the duration of the billing statistics
	// upload.
	uploadDuration prometheus.Histogram
}

// NewBillstat registers the billing-statistics metrics in reg and returns a
// properly initialized [Billstat].
func NewBillstat(namespace string, reg prometheus.Registerer) (m *Billstat, err error) {
	const (
		bufSize         = "buf_size"
		uploadStatus    = "bill_stat_upload_status"
		uploadTimestamp = "bill_stat_upload_timestamp"
		uploadDuration  = "bill_stat_upload_duration"
	)

	m = &Billstat{
		bufSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      bufSize,
			Namespace: namespace,
			Subsystem: subsystemBillStat,
			Help:      "Count of records in the local billstat DB.",
		}),
		uploadStatus: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      uploadStatus,
			Namespace: namespace,
			Subsystem: subsystemBillStat,
			Help:      "Status of the last billstat upload.",
		}),
		uploadTimestamp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      uploadTimestamp,
			Namespace: namespace,
			Subsystem: subsystemBillStat,
			Help:      "Time when the billing statistics were uploaded last time.",
		}),
		uploadDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:      uploadDuration,
			Namespace: namespace,
			Subsystem: subsystemBillStat,
			Help:      "Time elapsed on uploading billing statistics to the backend.",
			Buckets:   []float64{0.001, 0.01, 0.1, 1, 5, 10, 30, 60, 120},
		}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   bufSize,
		Value: m.bufSize,
	}, {
		Key:   uploadStatus,
		Value: m.uploadStatus,
	}, {
		Key:   uploadTimestamp,
		Value: m.uploadTimestamp,
	}, {
		Key:   uploadDuration,
		Value: m.uploadDuration,
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

// BufferSizeSet implements the [billstat.Metrics] interface for *Billstat.
func (m *Billstat) BufferSizeSet(_ context.Context, n float64) {
	m.bufSize.Set(n)
}

// HandleUploadDuration implements the [billstat.Metrics] interface for
// *Billstat.
func (m *Billstat) HandleUploadDuration(_ context.Context, dur float64, isSuccess bool) {
	m.uploadDuration.Observe(dur)

	if isSuccess {
		m.uploadTimestamp.SetToCurrentTime()
		m.uploadStatus.Set(1)
	} else {
		m.uploadStatus.Set(0)
	}
}
