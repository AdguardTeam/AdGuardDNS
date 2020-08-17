package dnsfilter

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
)

// Variables declared for monitoring.
var (
	requests = newCounter("requests_total", "Count of requests seen by dnsfilter.")
	filtered = newCounter("filtered_total", "Count of requests filtered by dnsfilter.")

	filteredLists        = newCounter("filtered_lists_total", "Count of requests filtered by dnsfilter using lists.")
	filteredSafeBrowsing = newCounter("filtered_safebrowsing_total", "Count of requests filtered by dnsfilter using safebrowsing.")
	filteredParental     = newCounter("filtered_parental_total", "Count of requests filtered by dnsfilter using parental.")
	safeSearch           = newCounter("safesearch_total", "Count of requests replaced by dnsfilter safesearch.")

	errorsTotal = newCounter("errors_total", "Count of requests that dnsfilter couldn't process because of transitive errors.")

	requestsSafeBrowsingTXT = newCounter("requests_safebrowsing", "Safe-browsing TXT requests number.")
	requestsParentalTXT     = newCounter("requests_parental", "Parental-control TXT requests number.")

	elapsedTime       = newHistogram("request_duration", "Histogram of the time (in seconds) each request took.")
	elapsedFilterTime = newHistogram("filter_duration", "Histogram of the time (in seconds) filtering of each request took.")

	engineTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      "engine_timestamp",
		Help:      "Last time when the engines were initialized.",
	}, []string{"filter"})

	engineSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      "engine_size",
		Help:      "Count of rules in the filtering engine.",
	}, []string{"filter"})

	engineStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      "engine_status",
		Help:      "Status of the filtering engine (1 for loaded successfully).",
	}, []string{"filter"})

	statsCacheSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      "stats_cache_size",
		Help:      "Count of recorded rule hits not yet dumped.",
	})

	statsUploadStatus = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      "stats_upload_status",
		Help:      "Status of the last stats upload.",
	})

	statsUploadTimestamp = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      "stats_upload_timestamp",
		Help:      "Time when stats where uploaded last time.",
	})
)

func newCounter(name string, help string) prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      name,
		Help:      help,
	})
}

func newHistogram(name string, help string) prometheus.Histogram {
	return prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      name,
		Help:      help,
	})
}
