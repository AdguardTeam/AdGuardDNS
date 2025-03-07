package metrics

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// DNSCheck is the Prometheus-based implementation of the [dnscheck.Metrics]
// interface.
type DNSCheck struct {
	// requestTotal is a counter with the total number of dnscheck requests
	// labeled by type and validity.
	requestTotal *prometheus.CounterVec

	// errorTotal is a gauge with the total number of errors occurred with
	// dnscheck requests labeled by request and error types.
	errorTotal *prometheus.GaugeVec
}

// NewDNSCheck registers the DNS checker metrics in reg and returns a properly
// initialized [*DNSCheck].
func NewDNSCheck(namespace string, reg prometheus.Registerer) (m *DNSCheck, err error) {
	const (
		reqTotal = "request_total"
		errTotal = "error_total"
	)

	m = &DNSCheck{
		requestTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      reqTotal,
			Namespace: namespace,
			Subsystem: subsystemDNSCheck,
			Help:      "The number of requests to the DNSCheck service.",
		}, []string{"type", "valid"}),
		errorTotal: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      errTotal,
			Namespace: namespace,
			Subsystem: subsystemDNSCheck,
			Help:      "The total number of errors with requests to the DNSCheck service.",
		}, []string{"source", "type"}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   reqTotal,
		Value: m.requestTotal,
	}, {
		Key:   errTotal,
		Value: m.errorTotal,
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

// HandleError implements the [dnscheck.Metrics] interface for *DNSCheck.
// reqType must be "dns" or "http".  errType must be either "timeout",
// "ratelimit", "other" or an empty string.
func (m *DNSCheck) HandleError(_ context.Context, reqType, errType string) {
	if errType == "" {
		return
	}

	m.errorTotal.WithLabelValues(reqType, errType).Inc()
}

// HandleRequest implements the [dnscheck.Metrics] interface for *DNSCheck.
// reqType must be "dns" or "http".
func (m *DNSCheck) HandleRequest(_ context.Context, reqType string, isValid bool) {
	m.requestTotal.WithLabelValues(reqType, BoolString(isValid)).Inc()
}
