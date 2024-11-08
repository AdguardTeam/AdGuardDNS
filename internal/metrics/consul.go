package metrics

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// Allowlist is the Prometheus-based implementation of the [consul.Metrics]
// interface.
type Allowlist struct {
	// size is a gauge with the number of loaded records in the ratelimit
	// allowlist.
	size prometheus.Gauge

	// updateStatus is a gauge with the status of the last ratelimit allowlist
	// update.  1 means success.
	updateStatus prometheus.Gauge

	// updateTime is a gauge with the timestamp of the last ratelimit allowlist
	// update.
	updateTime prometheus.Gauge
}

// NewAllowlist registers the Consul allowlist metrics in reg and returns a
// properly initialized [Allowlist].
func NewAllowlist(
	namespace string,
	reg prometheus.Registerer,
	typ string,
) (m *Allowlist, err error) {
	switch typ {
	case subsystemBackend, subsystemConsul:
		// Go on.
	default:
		return nil, fmt.Errorf("subsystem: %w: %q", errors.ErrBadEnumValue, typ)
	}

	const (
		size         = "allowlist_size"
		updateStatus = "allowlist_update_status"
		updateTime   = "allowlist_update_timestamp"
	)

	labels := prometheus.Labels{"type": typ}

	m = &Allowlist{
		size: prometheus.NewGauge(prometheus.GaugeOpts{
			Subsystem:   subsystemRateLimit,
			Namespace:   namespace,
			Name:        size,
			Help:        "Size of the loaded ratelimit allowlist.",
			ConstLabels: labels,
		}),
		updateStatus: prometheus.NewGauge(prometheus.GaugeOpts{
			Subsystem:   subsystemRateLimit,
			Namespace:   namespace,
			Name:        updateStatus,
			Help:        "Status of the last ratelimit allowlist update. 1 means success.",
			ConstLabels: labels,
		}),
		updateTime: prometheus.NewGauge(prometheus.GaugeOpts{
			Subsystem:   subsystemRateLimit,
			Namespace:   namespace,
			Name:        updateTime,
			Help:        "Timestamp of the last ratelimit allowlist update.",
			ConstLabels: labels,
		}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   size,
		Value: m.size,
	}, {
		Key:   updateStatus,
		Value: m.updateStatus,
	}, {
		Key:   updateTime,
		Value: m.updateTime,
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

// SetSize implements the [consul.Metrics] interface for *Allowlist.
func (m *Allowlist) SetSize(_ context.Context, n int) {
	m.size.Set(float64(n))
}

// SetStatus implements the [consul.Metrics] interface for *Allowlist.
func (m *Allowlist) SetStatus(_ context.Context, err error) {
	m.updateTime.SetToCurrentTime()
	SetStatusGauge(m.updateStatus, err)
}
