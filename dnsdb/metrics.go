package dnsdb

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	dbSizeGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsdb",
		Name:      "db_size",
		Help:      "Count of records in the local DNSDB.",
	})
	bufferSizeGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsdb",
		Name:      "buffer_size",
		Help:      "Count of records in the temporary buffer.",
	})
	dbRotateTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsdb",
		Name:      "rotate_time",
		Help:      "Time when the database was rotated.",
	})
	elapsedDBSave = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsdb",
		Name:      "elapsed_db_save",
		Help:      "Time elapsed on saving buffer to the database.",
	})
)
