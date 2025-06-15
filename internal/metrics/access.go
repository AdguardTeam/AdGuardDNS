package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// AccessProfile is the Prometheus-based implementation of the
// [access.ProfileMetrics] interface.
type AccessProfile struct {
	// accessProfileInitDuration is a histogram with the duration of a profile
	// access internal engine initialization.
	accessProfileInitDuration prometheus.Histogram
}

// NewAccessProfile registers the profile access engine metrics in reg and
// returns a properly initialized [AccessProfile].
func NewAccessProfile(namespace string, reg prometheus.Registerer) (m *AccessProfile, err error) {
	const (
		accessProfileInitDuration = "profile_init_engine_duration_seconds"
	)

	m = &AccessProfile{
		accessProfileInitDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:      accessProfileInitDuration,
			Namespace: namespace,
			Subsystem: subsystemAccess,
			Help:      "Time elapsed on profile access engine initialization.",
			Buckets:   []float64{0.001, 0.01, 0.1, 1},
		}),
	}

	err = reg.Register(m.accessProfileInitDuration)
	if err != nil {
		return nil, fmt.Errorf("registering metrics %q: %w", accessProfileInitDuration, err)
	}

	return m, nil
}

// ObserveProfileInit implements the [access.Metrics] interface for
// *AccessProfile.
func (m *AccessProfile) ObserveProfileInit(_ context.Context, dur time.Duration) {
	m.accessProfileInitDuration.Observe(dur.Seconds())
}
