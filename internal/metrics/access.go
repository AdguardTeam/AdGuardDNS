package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// AccessProfileInitDuration is a histogram with the duration of a profile
// access internal engine initialization.
var AccessProfileInitDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:      "profile_init_engine_duration_seconds",
	Namespace: namespace,
	Subsystem: subsystemAccess,
	Help:      "Time elapsed on profile access engine initialization.",
})
