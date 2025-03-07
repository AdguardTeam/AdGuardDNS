package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// ConnLimiterConnMetricsData is an alias for a structure that contains
// information about a stream-connection.  All fields must not be empty.
//
// See [connlimiter.ConnMetricsData].
type ConnLimiterConnMetricsData = struct {
	// Addr is the address that the server is configured to listen on.
	Addr string

	// Name is the name of the server.
	Name string

	// Proto is the protocol of the server.
	Proto string
}

// ConnLimiter is a Prometheus-based implementation of the [connlimiter.Metrics]
// interface.
type ConnLimiter struct {
	// activeConnections is the metrics gauge of currently active stream
	// connections.
	activeConnections *prometheus.GaugeVec

	// lifeDuration is a histogram with the duration of stream connection lives.
	lifeDuration *prometheus.HistogramVec

	// limits is the gauge vector for showing the configured limits for active
	// stream connections.
	limits *prometheus.GaugeVec

	// waitingDuration is a histogram with the duration of waiting times for
	// accepting stream connections.
	waitingDuration *prometheus.HistogramVec
}

// NewConnLimiter registers the stream-connections metrics in reg and returns a
// properly initialized [*ConnLimiter].
func NewConnLimiter(namespace string, reg prometheus.Registerer) (m *ConnLimiter, err error) {
	const (
		activeConnections = "active_stream_conns"
		lifeDuration      = "stream_conn_life_duration_seconds"
		limits            = "limits"
		waitingDuration   = "stream_conn_wait_duration_seconds"
	)

	m = &ConnLimiter{
		activeConnections: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      activeConnections,
			Subsystem: subsystemConnLimiter,
			Namespace: namespace,
			Help:      `The number of currently active stream-connections.`,
		}, []string{"name", "proto", "addr"}),
		lifeDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:      lifeDuration,
			Subsystem: subsystemConnLimiter,
			Namespace: namespace,
			Help:      "How long a stream connection lives, in seconds.",
			Buckets:   []float64{0.1, 1, 5, 10, 30, 60},
		}, []string{"name", "proto", "addr"}),
		limits: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      limits,
			Namespace: namespace,
			Subsystem: subsystemConnLimiter,
			Help: `The current limits of the number of active stream-connections: ` +
				`kind="stop" for the stopping limit and kind="resume" for the resuming one.`,
		}, []string{"kind"}),
		waitingDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:      waitingDuration,
			Subsystem: subsystemConnLimiter,
			Namespace: namespace,
			Help:      "How long a stream connection waits for an accept, in seconds.",
			Buckets:   []float64{0.00001, 0.01, 0.1, 1, 10, 30, 60},
		}, []string{"name", "proto", "addr"}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   activeConnections,
		Value: m.activeConnections,
	}, {
		Key:   lifeDuration,
		Value: m.lifeDuration,
	}, {
		Key:   limits,
		Value: m.limits,
	}, {
		Key:   waitingDuration,
		Value: m.waitingDuration,
	}}

	for _, c := range collectors {
		err = reg.Register(c.Value)
		if err != nil {
			errs = append(errs, fmt.Errorf("registering metrics %q: %w", c.Key, err))
		}
	}

	if err = errors.Join(errs...); err != nil {
		return nil, err
	}

	return m, nil
}

// IncrementActive implements the [Metrics] interface for *ConnLimiter.
func (c *ConnLimiter) IncrementActive(_ context.Context, m *ConnLimiterConnMetricsData) {
	c.activeConnections.WithLabelValues(m.Name, m.Proto, m.Addr).Inc()
}

// DecrementActive implements the [Metrics] interface for *ConnLimiter.
func (c *ConnLimiter) DecrementActive(_ context.Context, m *ConnLimiterConnMetricsData) {
	c.activeConnections.WithLabelValues(m.Name, m.Proto, m.Addr).Dec()
}

// ObserveLifeDuration implements the [Metrics] interface for *ConnLimiter.
func (c *ConnLimiter) ObserveLifeDuration(
	_ context.Context,
	m *ConnLimiterConnMetricsData,
	dur time.Duration,
) {
	c.lifeDuration.WithLabelValues(m.Name, m.Proto, m.Addr).Observe(dur.Seconds())
}

// ObserveWaitingDuration implements the [Metrics] interface for *ConnLimiter.
func (c *ConnLimiter) ObserveWaitingDuration(
	_ context.Context,
	m *ConnLimiterConnMetricsData,
	dur time.Duration,
) {
	c.waitingDuration.WithLabelValues(m.Name, m.Proto, m.Addr).Observe(dur.Seconds())
}

// SetStopLimit implements the [Metrics] interface for *ConnLimiter.
func (c *ConnLimiter) SetStopLimit(_ context.Context, n uint64) {
	c.limits.WithLabelValues("stop").Set(float64(n))
}

// SetResumeLimit implements the [Metrics] interface for *ConnLimiter.
func (c *ConnLimiter) SetResumeLimit(_ context.Context, n uint64) {
	c.limits.WithLabelValues("resume").Set(float64(n))
}
