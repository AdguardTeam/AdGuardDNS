package metrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

// SetExperimentGauge the gauge used to inform about running experiments.  reg
// must not be nil.
func SetExperimentGauge(reg prometheus.Registerer, constLabels prometheus.Labels) (err error) {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:      "experiment_enabled",
		Namespace: namespace,
		Subsystem: subsystemResearch,
		Help: `A metric with a constant value of 1 labeled by experiments that are available ` +
			`and enabled.`,
		ConstLabels: constLabels,
	})

	err = reg.Register(gauge)
	if err != nil {
		return fmt.Errorf("registering experiment_enabled metric: %w", err)
	}

	gauge.Set(1)

	return nil
}
