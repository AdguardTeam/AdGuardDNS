package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ConnLimiterLimits is the gauge vector for showing the configured limits of
// the number of active stream-connections.
var ConnLimiterLimits = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name:      "limits",
	Namespace: namespace,
	Subsystem: subsystemConnLimiter,
	Help: `The current limits of the number of active stream-connections: ` +
		`kind="stop" for the stopping limit and kind="resume" for the resuming one.`,
}, []string{"kind"})

// ConnLimiterActiveStreamConns is the gauge vector for the number of active
// stream-connections.
var ConnLimiterActiveStreamConns = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name:      "active_stream_conns",
	Namespace: namespace,
	Subsystem: subsystemConnLimiter,
	Help:      `The number of currently active stream-connections.`,
}, []string{"name", "proto", "addr"})

// StreamConnWaitDuration is a histogram with the duration of waiting times for
// accepting stream connections.
var StreamConnWaitDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:      "stream_conn_wait_duration_seconds",
	Subsystem: subsystemConnLimiter,
	Namespace: namespace,
	Help:      "How long a stream connection waits for an accept, in seconds.",
	Buckets:   []float64{0.00001, 0.01, 0.1, 1, 10, 30, 60},
}, []string{"name", "proto", "addr"})

// StreamConnLifeDuration is a histogram with the duration of lives of stream
// connections.
var StreamConnLifeDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:      "stream_conn_life_duration_seconds",
	Subsystem: subsystemConnLimiter,
	Namespace: namespace,
	Help:      "How long a stream connection lives, in seconds.",
	Buckets:   []float64{0.1, 1, 5, 10, 30, 60},
}, []string{"name", "proto", "addr"})
