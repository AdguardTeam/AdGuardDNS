package refuseany

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

func newDNSCounter(name string, help string) prometheus.Counter {
	return promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "refuseany",
		Name:      name,
		Help:      help,
	})
}

var (
	refusedAnyTotal = newDNSCounter("refusedany_total", "Count of ANY requests that have been dropped")
)
