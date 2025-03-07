package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// Filter is the Prometheus-based implementation of the [Filter]
// interface.
type Filter struct {
	// rulesTotal is the gauge vector with the number of rules loaded by each
	// filter.
	rulesTotal *prometheus.GaugeVec

	// updateStatus is the gauge vector with status of the last filter update.
	// "0" means error, "1" means success.
	updateStatus *prometheus.GaugeVec

	// updateTime is the gauge vector with the last time when the filter was
	// last updated.
	updatedTime *prometheus.GaugeVec
}

// NewFilter registers the filtering metrics in reg and returns a properly
// initialized *Filter.
func NewFilter(namespace string, reg prometheus.Registerer) (m *Filter, err error) {
	const (
		rulesTotal   = "rules_total"
		updateStatus = "update_status"
		updatedTime  = "updated_time"
	)

	m = &Filter{
		rulesTotal: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      rulesTotal,
			Subsystem: subsystemFilter,
			Namespace: namespace,
			Help:      "The number of rules loaded by filters.",
		}, []string{"filter"}),

		updateStatus: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      updateStatus,
			Subsystem: subsystemFilter,
			Namespace: namespace,
			Help:      "Status of the filter update. 1 means success.",
		}, []string{"filter"}),

		updatedTime: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      updatedTime,
			Subsystem: subsystemFilter,
			Namespace: namespace,
			Help:      "Time when the filter was last time updated.",
		}, []string{"filter"}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   rulesTotal,
		Value: m.rulesTotal,
	}, {
		Key:   updateStatus,
		Value: m.updateStatus,
	}, {
		Key:   updatedTime,
		Value: m.updatedTime,
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

// SetFilterStatus implements the [filter.Metrics] interface for *Filter.
func (m *Filter) SetFilterStatus(
	_ context.Context,
	id string,
	updTime time.Time,
	ruleCount int,
	err error,
) {
	if err != nil {
		m.updateStatus.WithLabelValues(id).Set(0)

		return
	}

	m.rulesTotal.WithLabelValues(id).Set(float64(ruleCount))
	m.updateStatus.WithLabelValues(id).Set(1)
	m.updatedTime.WithLabelValues(id).Set(float64(updTime.UnixNano()) / float64(time.Second))
}
