package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// AccessBlockedForSubnetTotal is a counter with the total count of requests
// blocked for client's subnet by global access manager.
var AccessBlockedForSubnetTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name:      "blocked_subnet_total",
	Namespace: namespace,
	Subsystem: subsystemAccess,
	Help:      "Total count of blocked subnet requests.",
})

// AccessBlockedForHostTotal is a counter with the total count of requests
// blocked for request's host by global access manager.
var AccessBlockedForHostTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name:      "blocked_host_total",
	Namespace: namespace,
	Subsystem: subsystemAccess,
	Help:      "Total count of blocked host requests.",
})

// AccessBlockedForProfileTotal is a counter with the total count of requests
// blocked for all profiles by access manager.
var AccessBlockedForProfileTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name:      "profile_blocked_total",
	Namespace: namespace,
	Subsystem: subsystemAccess,
	Help:      "Total count of blocked profile requests.",
})

// AccessProfileInitDuration is a histogram with the duration of a profile
// access internal engine initialization.
var AccessProfileInitDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:      "profile_init_engine_duration_seconds",
	Namespace: namespace,
	Subsystem: subsystemAccess,
	Help:      "Time elapsed on profile access engine initialization.",
})
