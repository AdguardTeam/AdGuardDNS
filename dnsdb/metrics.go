package dnsdb

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	dbSizeGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsdb",
		Name:      "db_size",
		Help:      "Count of records in the local DNSDB.",
	})
	bufferSizeGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsdb",
		Name:      "buffer_size",
		Help:      "Count of records in the temporary buffer.",
	})
	dbRotateTimestamp = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsdb",
		Name:      "rotate_time",
		Help:      "Time when the database was rotated.",
	})
	elapsedDBSave = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsdb",
		Name:      "elapsed_db_save",
		Help:      "Time elapsed on saving buffer to the database.",
	})
)
