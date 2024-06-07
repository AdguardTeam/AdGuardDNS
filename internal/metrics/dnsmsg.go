package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics related to DNS-message handling.
var (
	// fullClones is a counter with the total number of cloned messages using
	// our custom cloner.  "full" is either "1" (cloned entirely using the
	// cloner) or "0" (cloned using miekg/dns.Copy).
	fullClones = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "total_full_clones",
		Subsystem: subsystemDNSMsg,
		Namespace: namespace,
		Help: "Total number of (not) full clones using the cloner. " +
			"full=1 means that a message was cloned fully using the cloner.",
	}, []string{"full"})

	// dnsMsgFullClones is a counter with the total number of ECS cache full
	// clones.
	dnsMsgFullClones = fullClones.With(prometheus.Labels{
		"full": "1",
	})

	// dnsMsgPartialClones is a counter with the total number of ECS cache
	// partial clones.
	dnsMsgPartialClones = fullClones.With(prometheus.Labels{
		"full": "0",
	})
)

// ClonerStat is the Prometheus-based implementation of the [dnsmsg.ClonerStat]
// interface.
type ClonerStat struct{}

// The type check is performed in the test file to prevent a dependency.

// OnClone implements the [dnsmsg.ClonerStat] interface for ClonerStat.
func (ClonerStat) OnClone(isFull bool) {
	IncrementCond(isFull, dnsMsgFullClones, dnsMsgPartialClones)
}
