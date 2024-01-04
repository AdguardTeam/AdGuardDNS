package metrics

import (
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

// ResearchData contains data for research metrics.
type ResearchData struct {
	OriginalResponse *dns.Msg
	FilterID         string
	Country          string
	TopSubdivision   string
	Host             string
	QType            uint16
	Blocked          bool
}

// ReportResearch reports metrics to prometheus that we may need to conduct
// researches.  If researchLogs is true, this method may also write additional
// INFO-level logs.
func ReportResearch(data *ResearchData, researchLogs bool) {
	ctry := data.Country

	var subdiv string
	if model.LabelValue(data.TopSubdivision).IsValid() {
		subdiv = data.TopSubdivision
	}

	if data.Blocked {
		reportResearchBlocked(data.FilterID, ctry, subdiv)
	}

	reportResearchRequest(ctry, subdiv)

	if data.QType == dns.TypeHTTPS {
		reportResearchECH(data.Host, data.OriginalResponse, researchLogs)
	}
}

// reportResearchECH checks if the response has ECH config and if it does,
// reports to metrics and writes to log.
func reportResearchECH(host string, origResp *dns.Msg, researchLogs bool) {
	if origResp == nil {
		return
	}

	for _, rr := range origResp.Answer {
		svcb, ok := rr.(*dns.HTTPS)
		if !ok {
			continue
		}

		reportECHConfig(svcb.SVCB, researchLogs, host)
	}
}

// reportECHConfig iterates over SVCB records, finds records with ECH
// configuration, reports to metrics, and if researchLogs is enabled writes to
// log.
func reportECHConfig(svcb dns.SVCB, researchLogs bool, host string) {
	for _, v := range svcb.Value {
		if v.Key() != dns.SVCB_ECHCONFIG {
			continue
		}

		ResearchResponseECH.Inc()

		if researchLogs {
			log.Info("research: ech-enabled: %q", host)
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
