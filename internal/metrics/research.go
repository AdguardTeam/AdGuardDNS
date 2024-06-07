package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ExperimentGauge returns the gauge used to inform about running experiments.
func ExperimentGauge(constLabels prometheus.Labels) (g prometheus.Gauge) {
	return promauto.NewGauge(
		prometheus.GaugeOpts{
			Name:      "experiment_enabled",
			Namespace: namespace,
			Subsystem: subsystemResearch,
			Help: `A metric with a constant value of 1 labeled by experiments that are available ` +
				`and enabled.`,
			ConstLabels: constLabels,
		},
	)
}
