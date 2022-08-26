package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// RuleStatCacheSize is a gauge with the count of recorded rule hits not
	// yet uploaded.
	RuleStatCacheSize = promauto.NewGauge(prometheus.GaugeOpts{
		Name:      "stats_cache_size",
		Namespace: namespace,
		Subsystem: subsystemRuleStat,
		Help:      "Count of recorded rule hits not yet dumped.",
	})
	// RuleStatUploadStatus is a gauge with the status of the last stats upload.
	RuleStatUploadStatus = promauto.NewGauge(prometheus.GaugeOpts{
		Name:      "stats_upload_status",
		Namespace: namespace,
		Subsystem: subsystemRuleStat,
		Help:      "Status of the last stats upload.",
	})
	// RuleStatUploadTimestamp is a gauge with the timestamp of the last stats
	// upload.
	RuleStatUploadTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name:      "stats_upload_timestamp",
		Namespace: namespace,
		Subsystem: subsystemRuleStat,
		Help:      "Time when stats were uploaded last time.",
	})
)
