package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ResearchRequestsPerCountryTotal counts the total number of queries per
// country from anonymous users.
var ResearchRequestsPerCountryTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name:      "requests_per_country_total",
	Namespace: namespace,
	Subsystem: subsystemResearch,
	Help:      "The total number of DNS queries per country from anonymous users.",
}, []string{"country"})

// ResearchBlockedRequestsPerCountryTotal counts the number of blocked queries
// per country from anonymous users.
var ResearchBlockedRequestsPerCountryTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name:      "blocked_per_country_total",
	Namespace: namespace,
	Subsystem: subsystemResearch,
	Help:      "The number of blocked DNS queries per country from anonymous users.",
}, []string{"filter", "country"})

// ReportResearchMetrics reports metrics to prometheus that we may need to
// conduct researches.
//
// TODO(ameshkov): use [agd.Profile] arg when recursive dependency is resolved.
func ReportResearchMetrics(
	anonymous bool,
	filteringEnabled bool,
	asn string,
	ctry string,
	filterID string,
	blocked bool,
) {
	// The current research metrics only count queries that come to public
	// DNS servers where filtering is enabled.
	if !filteringEnabled || !anonymous {
		return
	}

	// Ignore AdGuard ASN specifically in order to avoid counting queries that
	// come from the monitoring.  This part is ugly, but since these metrics
	// are a one-time deal, this is acceptable.
	//
	// TODO(ameshkov): think of a better way later if we need to do that again.
	if asn == "212772" {
		return
	}

	if blocked {
		ResearchBlockedRequestsPerCountryTotal.WithLabelValues(
			filterID,
			ctry,
		).Inc()
	}

	ResearchRequestsPerCountryTotal.WithLabelValues(ctry).Inc()
}
