package metrics

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// InitialMiddleware is the Prometheus-based implementation of the
// [dnssvc.InitialMiddlewareMetrics] interface.
type InitialMiddleware struct {
	specialRequestsTotal *prometheus.CounterVec
}

// NewInitialMiddleware registers the filtering-middleware metrics in reg and
// returns a properly initialized *InitialMiddleware.  All arguments must be
// set.
func NewInitialMiddleware(
	namespace string,
	reg prometheus.Registerer,
) (m *InitialMiddleware, err error) {
	const (
		specialRequestsTotal = "special_requests_total"
	)

	m = &InitialMiddleware{
		specialRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      specialRequestsTotal,
			Namespace: namespace,
			Subsystem: subsystemDNSSvc,
			Help:      "The number of DNS requests for special domain names.",
		}, []string{"kind"}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   specialRequestsTotal,
		Value: m.specialRequestsTotal,
	}}

	for _, c := range collectors {
		err = reg.Register(c.Value)
		if err != nil {
			errs = append(errs, fmt.Errorf("registering metrics %q: %w", c.Key, err))
		}
	}

	if err = errors.Join(errs...); err != nil {
		return nil, err
	}

	return m, nil
}

// IncrementRequestsTotal implements the [Metrics] interface for
// *InitialMiddleware.
func (m *InitialMiddleware) IncrementRequestsTotal(_ context.Context, kind string) {
	m.specialRequestsTotal.WithLabelValues(kind).Inc()
}
