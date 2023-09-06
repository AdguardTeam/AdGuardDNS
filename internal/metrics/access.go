package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// AccessBlockedForSubnetTotal is a counter with the total count of request
// blocked for client's subnet by access manager.
//
// TODO(d.kolyshev): Consider adding rule label.
var AccessBlockedForSubnetTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name:      "blocked_subnet_total",
	Namespace: namespace,
	Subsystem: subsystemAccess,
	Help:      "Total count of blocked subnet requests.",
})

// AccessBlockedForHostTotal is a counter with the total count of request
// blocked for request's host by access manager.
var AccessBlockedForHostTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name:      "blocked_host_total",
	Namespace: namespace,
	Subsystem: subsystemAccess,
	Help:      "Total count of blocked host requests.",
})
