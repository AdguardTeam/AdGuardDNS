package metrics

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// DeviceFinder is the Prometheus-based implementation of the
// [dnssvc.DeviceFinderMetrics] interface.
type DeviceFinder struct {
	customDomainMismatchesTotal *prometheus.CounterVec
	customDomainRequestsTotal   *prometheus.CounterVec
	dohAuthenticationFails      prometheus.Counter
	unknownDedicatedTotal       prometheus.Counter
}

// IncrementCustomDomainMismatches implements the [Metrics] interface for
// m *DeviceFinder.
func (m *DeviceFinder) IncrementCustomDomainMismatches(_ context.Context, domain string) {
	m.customDomainMismatchesTotal.WithLabelValues(domain).Inc()
}

// IncrementCustomDomainRequests implements the [Metrics] interface for
// m *DeviceFinder.
func (m *DeviceFinder) IncrementCustomDomainRequests(_ context.Context, domain string) {
	m.customDomainRequestsTotal.WithLabelValues(domain).Inc()
}

// IncrementDoHAuthenticationFails implements the [Metrics] interface for
// m *DeviceFinder.
func (m *DeviceFinder) IncrementDoHAuthenticationFails(_ context.Context) {
	m.dohAuthenticationFails.Inc()
}

// IncrementUnknownDedicated implements the [Metrics] interface for
// m *DeviceFinder.
func (m *DeviceFinder) IncrementUnknownDedicated(_ context.Context) {
	m.unknownDedicatedTotal.Inc()
}

// NewDeviceFinder registers the device-finder metrics in reg and returns a
// properly initialized *DeviceFinder.  All arguments must be set.
func NewDeviceFinder(namespace string, reg prometheus.Registerer) (m *DeviceFinder, err error) {
	const (
		customDomainMismatchesTotal = "custom_domain_matches_total"
		customDomainRequestsTotal   = "custom_domain_requests_total"
		dohAuthenticationFails      = "doh_authentication_fails"
		// TODO(a.garipov):  Consider renaming to "unknown_dedicated_total".
		unknownDedicatedTotal = "unknown_dedicated"
	)

	// TODO(a.garipov):  Consider creating a new subsystem.

	m = &DeviceFinder{
		customDomainMismatchesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      customDomainMismatchesTotal,
			Namespace: namespace,
			Subsystem: subsystemDNSSvc,
			Help: "The number of requests from devices that do not belong to the profile " +
				"which the custom domain belongs to.",
		}, []string{"domain"}),

		customDomainRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      customDomainRequestsTotal,
			Namespace: namespace,
			Subsystem: subsystemDNSSvc,
			Help: "The total number requests recognized as being to a custom domain " +
				"belonging to a profile.",
		}, []string{"domain"}),

		dohAuthenticationFails: prometheus.NewCounter(prometheus.CounterOpts{
			Name:      dohAuthenticationFails,
			Namespace: namespace,
			Subsystem: subsystemDNSSvc,
			Help:      "The number of authentication failures for DoH auth.",
		}),

		unknownDedicatedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:      unknownDedicatedTotal,
			Namespace: namespace,
			Subsystem: subsystemDNSSvc,
			Help:      "The number of dropped queries for unrecognized dedicated addresses.",
		}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   customDomainMismatchesTotal,
		Value: m.customDomainMismatchesTotal,
	}, {
		Key:   customDomainRequestsTotal,
		Value: m.customDomainRequestsTotal,
	}, {
		Key:   dohAuthenticationFails,
		Value: m.dohAuthenticationFails,
	}, {
		Key:   unknownDedicatedTotal,
		Value: m.unknownDedicatedTotal,
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
