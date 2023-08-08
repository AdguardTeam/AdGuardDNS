package metrics

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/common/model"
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

// ResearchRequestsPerSubdivTotal counts the total number of queries per country
// from anonymous users.
var ResearchRequestsPerSubdivTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name:      "requests_per_subdivision_total",
	Namespace: namespace,
	Subsystem: subsystemResearch,
	Help: `The total number of DNS queries per countries with top ` +
		`subdivision from anonymous users.`,
}, []string{"country", "subdivision"})

// ResearchBlockedRequestsPerSubdivTotal counts the number of blocked queries
// per country from anonymous users.
var ResearchBlockedRequestsPerSubdivTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name:      "blocked_per_subdivision_total",
	Namespace: namespace,
	Subsystem: subsystemResearch,
	Help: `The number of blocked DNS queries per countries with top ` +
		`subdivision from anonymous users.`,
}, []string{"filter", "country", "subdivision"})

// ResearchResponseECH counts the number of DNS responses with a ECH config.
var ResearchResponseECH = promauto.NewCounter(prometheus.CounterOpts{
	Name:      "response_ech",
	Namespace: namespace,
	Subsystem: subsystemResearch,
	Help:      `The number of DNS responses with a ECH config.`,
})

// ReportResearch reports metrics to prometheus that we may need to conduct
// researches.  If researchLogs is true, this method may also write additional
// INFO-level logs.
func ReportResearch(
	ri *agd.RequestInfo,
	origResp *dns.Msg,
	filterID agd.FilterListID,
	blocked bool,
	researchLogs bool,
) {
	filteringEnabled := ri.FilteringGroup != nil &&
		ri.FilteringGroup.RuleListsEnabled &&
		len(ri.FilteringGroup.RuleListIDs) > 0

	// The current research metrics only count queries that come to public DNS
	// servers where filtering is enabled.
	if !filteringEnabled || ri.Profile != nil {
		return
	}

	var ctry, subdiv string
	if l := ri.Location; l != nil {
		// Ignore AdGuard ASN specifically in order to avoid counting queries
		// that come from the monitoring.  This part is ugly, but since these
		// metrics are a one-time deal, this is acceptable.
		//
		// TODO(ameshkov): Think of a better way later if we need to do that
		// again.
		if l.ASN == 212772 {
			return
		}

		ctry = string(l.Country)
		if model.LabelValue(l.TopSubdivision).IsValid() {
			subdiv = l.TopSubdivision
		}
	}

	if blocked {
		reportResearchBlocked(string(filterID), ctry, subdiv)
	}

	reportResearchRequest(ctry, subdiv)
	reportResearchECH(ri, origResp, researchLogs)
}

// reportResearchECH checks if the response has ECH config and if it does,
// reports to metrics and writes to log.
func reportResearchECH(ri *agd.RequestInfo, origResp *dns.Msg, researchLogs bool) {
	if origResp == nil || ri.QType != dns.TypeHTTPS {
		return
	}

	for _, rr := range origResp.Answer {
		if svcb, ok := rr.(*dns.HTTPS); ok {
			for _, v := range svcb.Value {
				if v.Key() == dns.SVCB_ECHCONFIG {
					ResearchResponseECH.Inc()

					if researchLogs {
						log.Info("research: ech-enabled: %s", ri.Host)
					}
				}
			}
		}
	}
}

// reportResearchBlocked reports on a blocked request to the research metrics.
func reportResearchBlocked(fltID, ctry, subdiv string) {
	ResearchBlockedRequestsPerCountryTotal.WithLabelValues(fltID, ctry).Inc()
	if subdiv != "" {
		ResearchBlockedRequestsPerSubdivTotal.WithLabelValues(fltID, ctry, subdiv).Inc()
	}
}

// reportResearchBlocked reports on a request to the research metrics.
func reportResearchRequest(ctry, subdiv string) {
	ResearchRequestsPerCountryTotal.WithLabelValues(ctry).Inc()
	if subdiv != "" {
		ResearchRequestsPerSubdivTotal.WithLabelValues(ctry, subdiv).Inc()
	}
}
