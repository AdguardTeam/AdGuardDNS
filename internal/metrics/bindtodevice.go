package metrics

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// BindToDevice is the Prometheus-based implementation of the
// [bindtodevice.Metrics] interface.
type BindToDevice struct {
	// unknownTCPRequestsTotal is the total counter of DNS requests over TCP to
	// unknown local addresses.
	unknownTCPRequestsTotal prometheus.Counter

	// unknownUDPRequestsTotal is the total counter of DNS requests over UDP to
	// unknown local addresses.
	unknownUDPRequestsTotal prometheus.Counter

	// tcpConnsChanSize is a gauge with the current number of TCP connections in
	// the buffer of the channel by each subnet.
	tcpConnsChanSize *prometheus.GaugeVec

	// udpSessionsChanSize is a gauge with the current number of UDP sessions in
	// the buffer of the channel by each subnet.
	udpSessionsChanSize *prometheus.GaugeVec

	// udpWriteRequestsChanSize is a gauge with the current number of UDP write
	// requests in the buffer of the channel for each interface listener.
	udpWriteRequestsChanSize *prometheus.GaugeVec

	// udpWriteDuration is a histogram of durations of UDP write operations.
	// This histogram includes only the write itself and does not include
	// deadline setting and resetting.
	udpWriteDuration *prometheus.HistogramVec
}

// NewBindToDevice registers the bindtodevice-related metrics in reg and returns
// a properly initialized *BindToDevice.
func NewBindToDevice(namespace string, reg prometheus.Registerer) (m *BindToDevice, err error) {
	// #nosec G101 -- There are no hardcoded credentials.
	const (
		unknownRequestsTotal     = "unknown_requests_total"
		tcpConnsChanSize         = "tcp_conns_chan_size"
		udpSessionsChanSize      = "udp_sessions_chan_size"
		udpWriteRequestsChanSize = "udp_write_requests_chan_size"
		udpWriteDuration         = "udp_write_duration_seconds"
	)

	unknownRequestsTotalCV := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      unknownRequestsTotal,
		Namespace: namespace,
		Subsystem: subsystemBindToDevice,
		Help:      "The total number of DNS requests to unknown local addresses.",
	}, []string{"proto"})

	m = &BindToDevice{
		unknownTCPRequestsTotal: unknownRequestsTotalCV.WithLabelValues("tcp"),
		unknownUDPRequestsTotal: unknownRequestsTotalCV.WithLabelValues("udp"),
		tcpConnsChanSize: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      tcpConnsChanSize,
			Namespace: namespace,
			Subsystem: subsystemBindToDevice,
			Help:      "The current number of TCP connections in the channel.",
		}, []string{"subnet"}),
		udpSessionsChanSize: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      udpSessionsChanSize,
			Namespace: namespace,
			Subsystem: subsystemBindToDevice,
			Help:      "The current number of UDP sessions in the channel.",
		}, []string{"subnet"}),
		udpWriteRequestsChanSize: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      udpWriteRequestsChanSize,
			Namespace: namespace,
			Subsystem: subsystemBindToDevice,
			Help:      "The current number of UDP write requests in the channel.",
		}, []string{"name"}),
		udpWriteDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:      udpWriteDuration,
			Namespace: namespace,
			Subsystem: subsystemBindToDevice,
			Help:      "The duration of a write to a UDP socket.",
			Buckets:   []float64{0.001, 0.01, 0.1, 1},
		}, []string{"name"}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   unknownRequestsTotal,
		Value: unknownRequestsTotalCV,
	}, {
		Key:   tcpConnsChanSize,
		Value: m.tcpConnsChanSize,
	}, {
		Key:   udpSessionsChanSize,
		Value: m.udpSessionsChanSize,
	}, {
		Key:   udpWriteRequestsChanSize,
		Value: m.udpWriteRequestsChanSize,
	}, {
		Key:   udpWriteDuration,
		Value: m.udpWriteDuration,
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

// IncrementUnknownTCPRequests implements the [bindtodevice.Metrics] interface
// for *BindToDevice.
func (m *BindToDevice) IncrementUnknownTCPRequests(context.Context) {
	m.unknownTCPRequestsTotal.Inc()
}

// IncrementUnknownUDPRequests implements the [bindtodevice.Metrics] interface
// for *BindToDevice.
func (m *BindToDevice) IncrementUnknownUDPRequests(context.Context) {
	m.unknownUDPRequestsTotal.Inc()
}

// SetTCPConnsChanSize implements the [bindtodevice.Metrics] interface for
// *BindToDevice.
func (m *BindToDevice) SetTCPConnsChanSize(_ context.Context, subnet netip.Prefix, n uint) {
	m.tcpConnsChanSize.WithLabelValues(subnet.String()).Set(float64(n))
}

// SetUDPSessionsChanSize implements the [bindtodevice.Metrics] interface for
// *BindToDevice.
func (m *BindToDevice) SetUDPSessionsChanSize(_ context.Context, subnet netip.Prefix, n uint) {
	m.udpSessionsChanSize.WithLabelValues(subnet.String()).Set(float64(n))
}

// SetUDPWriteRequestsChanSize implements the [bindtodevice.Metrics] interface
// for *BindToDevice.
func (m *BindToDevice) SetUDPWriteRequestsChanSize(_ context.Context, ifaceName string, n uint) {
	m.udpWriteRequestsChanSize.WithLabelValues(ifaceName).Set(float64(n))
}

// ObserveUDPWriteDuration implements the [bindtodevice.Metrics] interface for
// *BindToDevice.
func (m *BindToDevice) ObserveUDPWriteDuration(
	_ context.Context,
	ifaceName string,
	dur time.Duration,
) {
	m.udpWriteDuration.WithLabelValues(ifaceName).Observe(float64(dur.Seconds()))
}
