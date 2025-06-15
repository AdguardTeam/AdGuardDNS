package metrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

// ClonerStat is the Prometheus-based implementation of the [dnsmsg.ClonerStat]
// interface.
type ClonerStat struct {
	// dnsMsgFullClones is a counter with the total number of ECS cache full
	// clones.
	dnsMsgFullClones prometheus.Counter

	// dnsMsgPartialClones is a counter with the total number of ECS cache
	// partial clones.
	dnsMsgPartialClones prometheus.Counter
}

// NewClonerStat registers the Redis KV metrics in reg and returns a properly
// initialized [ClonerStat].
func NewClonerStat(namespace string, reg prometheus.Registerer) (m *ClonerStat, err error) {
	const (
		fullClonesTotal = "total_full_clones"
	)

	// fullClones is a counter with the total number of cloned messages using
	// our custom cloner.  "full" is either "1" (cloned entirely using the
	// cloner) or "0" (cloned using miekg/dns.Copy).
	fullClones := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      fullClonesTotal,
		Subsystem: subsystemDNSMsg,
		Namespace: namespace,
		Help: "Total number of (not) full clones using the cloner. " +
			"full=1 means that a message was cloned fully using the cloner.",
	}, []string{"full"})

	m = &ClonerStat{
		dnsMsgFullClones: fullClones.With(prometheus.Labels{
			"full": "1",
		}),
		dnsMsgPartialClones: fullClones.With(prometheus.Labels{
			"full": "0",
		}),
	}

	err = reg.Register(fullClones)
	if err != nil {
		return nil, fmt.Errorf("registering metrics %q: %w", fullClonesTotal, err)
	}

	return m, nil
}

// The type check is performed in the test file to prevent a dependency.

// OnClone implements the [dnsmsg.ClonerStat] interface for ClonerStat.
func (m *ClonerStat) OnClone(isFull bool) {
	IncrementCond(isFull, m.dnsMsgFullClones, m.dnsMsgPartialClones)
}
