package refuseany

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
)

func newDNSCounter(name string, help string) prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "refuseany",
		Name:      name,
		Help:      help,
	})
}

var (
	refusedAnyTotal = newDNSCounter("refusedany_total", "Count of ANY requests that have been dropped")
)
