package metrics

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// RuleStat is the Prometheus-based implementation of the [rulestat.Metrics]
// interface.
type RuleStat struct {
	// hitCount is a gauge with the count of recorded rule hits that have not
	// yet been uploaded.
	hitCount prometheus.Gauge

	// uploadStatus is a gauge with the status of the last stats upload.
	uploadStatus prometheus.Gauge

	// uploadTimestamp is a gauge with the timestamp of the last successful
	// stats upload.
	uploadTimestamp prometheus.Gauge
}

// NewRuleStat registers the filtering rule metrics in reg and returns a
// properly initialized [*RuleStat].
func NewRuleStat(namespace string, reg prometheus.Registerer) (m *RuleStat, err error) {
	const (
		// TODO(s.chzhen):  Check if this is correct.
		hitCount        = "stats_cache_size"
		uploadStatus    = "stats_upload_status"
		uploadTimestamp = "stats_upload_timestamp"
	)

	m = &RuleStat{
		hitCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      hitCount,
			Namespace: namespace,
			Subsystem: subsystemRuleStat,
			Help:      "Count of recorded rule hits not yet dumped.",
		}),
		uploadStatus: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      uploadStatus,
			Namespace: namespace,
			Subsystem: subsystemRuleStat,
			Help:      "Status of the last stats upload.",
		}),
		uploadTimestamp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      uploadTimestamp,
			Namespace: namespace,
			Subsystem: subsystemRuleStat,
			Help:      "Time when stats were uploaded last time.",
		}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   hitCount,
		Value: m.hitCount,
	}, {
		Key:   uploadStatus,
		Value: m.uploadStatus,
	}, {
		Key:   uploadTimestamp,
		Value: m.uploadTimestamp,
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

// SetHitCount implements the [rulestat.Metrics] interface for *RuleStat.
func (m *RuleStat) SetHitCount(_ context.Context, count int64) {
	m.hitCount.Set(float64(count))
}

// HandleUploadStatus implements the [rulestat.Metrics] interface for *RuleStat.
func (m *RuleStat) HandleUploadStatus(_ context.Context, err error) {
	if err != nil {
		m.uploadStatus.Set(0)

		return
	}

	m.uploadStatus.Set(1)
	m.uploadTimestamp.SetToCurrentTime()
}
