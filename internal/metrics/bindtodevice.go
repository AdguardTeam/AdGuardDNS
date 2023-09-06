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
	// of UDP write requests in the buffer of the channel by each subnet.
	BindToDeviceUDPWriteRequestsChanSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "udp_write_requests_chan_size",
		Namespace: namespace,
		Subsystem: subsystemBindToDevice,
		Help:      "The current number of UDP write requests in the channel.",
	}, []string{"subnet"})
)
