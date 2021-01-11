package dnsfilter

import (
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Variables declared for monitoring.
var (
	requests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      "requests_total",
		Help:      "Count of requests seen by dnsfilter per continent, country.",
	}, []string{"continent", "country"})

	filtered = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      "filtered_total",
		Help:      "Count of requests filtered by dnsfilter per continent, country.",
	}, []string{"continent", "country"})

	filteredLists        = newCounter("filtered_lists_total", "Count of requests filtered by dnsfilter using lists.")
	filteredSafeBrowsing = newCounter("filtered_safebrowsing_total", "Count of requests filtered by dnsfilter using safebrowsing.")
	filteredParental     = newCounter("filtered_parental_total", "Count of requests filtered by dnsfilter using parental.")
	safeSearch           = newCounter("safesearch_total", "Count of requests replaced by dnsfilter safesearch.")

	errorsTotal = newCounter("errors_total", "Count of requests that dnsfilter couldn't process because of transitive errors.")

	requestsSafeBrowsingTXT = newCounter("requests_safebrowsing", "Safe-browsing TXT requests number.")
	requestsParentalTXT     = newCounter("requests_parental", "Parental-control TXT requests number.")

	elapsedTime       = newHistogram("request_duration", "Histogram of the time (in seconds) each request took.")
	elapsedFilterTime = newHistogram("filter_duration", "Histogram of the time (in seconds) filtering of each request took.")

	engineTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      "engine_timestamp",
		Help:      "Last time when the engines were initialized.",
	}, []string{"filter"})

	engineSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      "engine_size",
		Help:      "Count of rules in the filtering engine.",
	}, []string{"filter"})

	engineStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      "engine_status",
		Help:      "Status of the filtering engine (1 for loaded successfully).",
	}, []string{"filter"})

	statsCacheSize = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      "stats_cache_size",
		Help:      "Count of recorded rule hits not yet dumped.",
	})

	statsUploadStatus = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      "stats_upload_status",
		Help:      "Status of the last stats upload.",
	})

	statsUploadTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      "stats_upload_timestamp",
		Help:      "Time when stats where uploaded last time.",
	})
)

func newCounter(name string, help string) prometheus.Counter {
	return promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      name,
		Help:      help,
	})
}

func newHistogram(name string, help string) prometheus.Histogram {
	return promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      name,
		Help:      help,
	})
}

// incRequests - increments requests metric (if necessary)
func incRequests(w dns.ResponseWriter) {
	_, country, continent := geoIP.getGeoData(w)
	requests.WithLabelValues(continent, country).Inc()
}

// incFiltered - increments filtered metric (if necessary)
func incFiltered(w dns.ResponseWriter) {
	_, country, continent := geoIP.getGeoData(w)
	filtered.WithLabelValues(continent, country).Inc()
}
