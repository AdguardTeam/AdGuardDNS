package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	specialRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "special_requests_total",
		Namespace: namespace,
		Subsystem: subsystemDNSSvc,
		Help:      "The number of DNS requests for special domain names.",
	}, []string{"kind"})

	// DNSSvcDDRRequestsTotal is a counter with total number of requests for
	// Discovery of Designated Resolvers.
	DNSSvcDDRRequestsTotal = specialRequestsTotal.With(prometheus.Labels{
		"kind": "ddr",
	})

	// DNSSvcBadResolverARPA is a counter with total number of requests for
	// malformed resolver.arpa queries.
	DNSSvcBadResolverARPA = specialRequestsTotal.With(prometheus.Labels{
		"kind": "bad_resolver_arpa",
	})

	// DNSSvcChromePrefetchRequestsTotal is a counter with total number of
	// requests for the domain name that Chrome uses to check if it should use
	// its prefetch proxy.
	DNSSvcChromePrefetchRequestsTotal = specialRequestsTotal.With(prometheus.Labels{
		"kind": "chrome_prefetch",
	})

	// DNSSvcFirefoxRequestsTotal is a counter with total number of requests for
	// the domain name that Firefox uses to check if it should use its own
	// DNS-over-HTTPS settings.
	DNSSvcFirefoxRequestsTotal = specialRequestsTotal.With(prometheus.Labels{
		"kind": "firefox",
	})

	// DNSSvcApplePrivateRelayRequestsTotal is a counter with total number of
	// requests for the domain name that Apple devices use to check if Apple
	// Private Relay can be enabled.
	DNSSvcApplePrivateRelayRequestsTotal = specialRequestsTotal.With(prometheus.Labels{
		"kind": "apple_private_relay",
	})

	// DNSSvcDoHAuthFailsTotal is the counter of DoH basic authentication
	// failures.
	DNSSvcDoHAuthFailsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name:      "doh_authentication_fails",
		Namespace: namespace,
		Subsystem: subsystemDNSSvc,
		Help:      "The number of authentication failures for DoH auth.",
	})
)
