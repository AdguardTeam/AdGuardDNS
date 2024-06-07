package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	bindToDeviceUnknownRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name:      "unknown_requests_total",
			Namespace: namespace,
			Subsystem: subsystemBindToDevice,
			Help:      "The total number of DNS requests to unknown local addresses.",
		},
		[]string{"proto"},
	)

	// BindToDeviceUnknownTCPRequestsTotal is the total counter of DNS requests
	// over TCP to unknown local addresses.
	BindToDeviceUnknownTCPRequestsTotal = bindToDeviceUnknownRequestsTotal.With(prometheus.Labels{
		"proto": "tcp",
	})

	// BindToDeviceUnknownUDPRequestsTotal is the total counter of DNS requests
	// over UDP to unknown local addresses.
	BindToDeviceUnknownUDPRequestsTotal = bindToDeviceUnknownRequestsTotal.With(prometheus.Labels{
		"proto": "udp",
	})
)

var (
	// BindToDeviceTCPConnsChanSize is a gauge with the current number of TCP
	// connections in the buffer of the channel by each subnet.
	BindToDeviceTCPConnsChanSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "tcp_conns_chan_size",
		Namespace: namespace,
		Subsystem: subsystemBindToDevice,
		Help:      "The current number of TCP connections in the channel.",
	}, []string{"subnet"})

	// BindToDeviceUDPSessionsChanSize is a gauge with the current number of UDP
	// sessions in the buffer of the channel by each subnet.
	BindToDeviceUDPSessionsChanSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "udp_sessions_chan_size",
		Namespace: namespace,
		Subsystem: subsystemBindToDevice,
		Help:      "The current number of UDP sessions in the channel.",
	}, []string{"subnet"})

	// BindToDeviceUDPWriteRequestsChanSize is a gauge with the current number
	// of UDP write requests in the buffer of the channel for each interface
	// listener.
	BindToDeviceUDPWriteRequestsChanSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "udp_write_requests_chan_size",
		Namespace: namespace,
		Subsystem: subsystemBindToDevice,
		Help:      "The current number of UDP write requests in the channel.",
	}, []string{"name"})

	// BindToDeviceUDPWriteDurationSeconds is a histogram of durations of UDP
	// write operations.  This histogram includes only the write itself and does
	// not include deadline setting and resetting.
	BindToDeviceUDPWriteDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:      "udp_write_duration_seconds",
		Namespace: namespace,
		Subsystem: subsystemBindToDevice,
		Help:      "The duration of a write to a UDP socket.",
		Buckets:   []float64{0.001, 0.01, 0.1, 1},
	}, []string{"name"})
)
