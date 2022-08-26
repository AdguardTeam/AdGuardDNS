package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// DNSCheckRequestTotal is a counter with the total number of dnscheck
// requests.  "type" can be "dns" or "http".  "valid" can be "1" or "0".
var DNSCheckRequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name:      "request_total",
	Namespace: namespace,
	Subsystem: subsystemDNSCheck,
	Help:      "The number of requests to the DNSCheck service.",
}, []string{"type", "valid"})
