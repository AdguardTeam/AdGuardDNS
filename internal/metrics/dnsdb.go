package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// DNSDBBufferSize is a gauge with the total count of records in the
	// in-memory temporary buffer.
	DNSDBBufferSize = promauto.NewGauge(prometheus.GaugeOpts{
		Name:      "buffer_size",
		Namespace: namespace,
		Subsystem: subsystemDNSDB,
		Help:      "Count of records in the in-memory buffer.",
	})

	// DNSDBRotateTime is a gauge with the time when the DNSDB was rotated.
	DNSDBRotateTime = promauto.NewGauge(prometheus.GaugeOpts{
		Name:      "rotate_time",
		Namespace: namespace,
		Subsystem: subsystemDNSDB,
		Help:      "Last time when the database was rotated.",
	})

	// DNSDBSaveDuration is a histogram with the time elapsed on rotating the
	// buffer for sending over HTTP.
	DNSDBSaveDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:      "save_duration",
		Namespace: namespace,
		Subsystem: subsystemDNSDB,
		Help:      "Time elapsed on rotating the buffer for sending over HTTP.",
	})
)
