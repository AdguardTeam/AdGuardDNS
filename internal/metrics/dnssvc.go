package metrics

import (
	"net/netip"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// DNSSvcRequestByCountryTotal is a counter with the total number of queries
// processed labeled by country and continent.
var DNSSvcRequestByCountryTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name:      "request_per_country_total",
	Namespace: namespace,
	Subsystem: subsystemDNSSvc,
	Help:      "The number of filtered DNS requests labeled by country and continent.",
}, []string{"continent", "country"})

// DNSSvcRequestByASNTotal is a counter with the total number of queries
// processed labeled by country and AS number.
var DNSSvcRequestByASNTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name:      "request_per_asn_total",
	Namespace: namespace,
	Subsystem: subsystemDNSSvc,
	Help:      "The number of filtered DNS requests labeled by country and ASN.",
}, []string{"country", "asn"})

// DNSSvcRequestByFilterTotal is a counter with the total number of queries
// processed labeled by filter.  "filter" contains the ID of the filter list
// applied.  "anonymous" is "0" if the request is from a AdGuard DNS customer,
// otherwise it is "1".
var DNSSvcRequestByFilterTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name:      "request_per_filter_total",
	Namespace: namespace,
	Subsystem: subsystemDNSSvc,
	Help:      "The number of filtered DNS requests labeled by filter applied.",
}, []string{"filter", "anonymous"})

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
)

// DNSSvcFilteringDuration is a histogram with the durations of actually
// filtering (e.g. applying filters, safebrowsing, etc) to queries.
var DNSSvcFilteringDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:      "filtering_duration_seconds",
	Namespace: namespace,
	Subsystem: subsystemDNSSvc,
	Help:      "Time elapsed on processing a DNS query.",
	// Filtering should be quite fast (microseconds) so the buckets were chosen
	// according to this.
	Buckets: []float64{
		// Starting from 1 microsecond
		0.000001,
		// 10 microseconds
		0.00001,
		// 50 microseconds
		0.00005,
		// 100 microseconds
		0.0001,
		// 1 millisecond
		0.001,
		// 10 milliseconds - if we got there, something went really wrong
		0.01,
		0.1,
		1,
	},
})

// usersCache is a helper structure where we keep for 1 hour the IP addresses
// of the DNS users.
//
// TODO(ameshkov): Consider making configurable.
var usersCache = cache.New(1*time.Hour, 1*time.Minute)

// dnsSvcUsersCount is a gauge with the number of DNS users for the last 1 hour.
var dnsSvcUsersCount = promauto.NewGauge(prometheus.GaugeOpts{
	Name:      "users_last_hour_count",
	Namespace: namespace,
	Subsystem: subsystemDNSSvc,
	Help:      "The number of DNS users for the last 1 hour.",
})

// DNSSvcUsersCountUpdate updates the dnsSvcUsersCount gauge with the new users
// count number.
func DNSSvcUsersCountUpdate(ip netip.Addr) {
	k := ip.String()
	_, ok := usersCache.Get(k)
	if !ok {
		usersCache.SetDefault(k, struct{}{})
	}

	dnsSvcUsersCount.Set(float64(usersCache.ItemCount()))
}
