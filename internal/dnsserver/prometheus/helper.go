package prometheus

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

// counterWithRequestLabels is a helper method that gets or creates a
// [prometheus.Counter] from the specified *prometheus.CounterVec.  The point of
// this method is to avoid allocating [prometheus.Labels] and instead use the
// WithLabelValues function.  This way extra allocations are avoided, but it is
// sensitive to the labels order.
func counterWithRequestLabels(
	serverInfo dnsserver.ServerInfo,
	req *dns.Msg,
	rw dnsserver.ResponseWriter,
	vec *prometheus.CounterVec,
) (c prometheus.Counter) {
	ip, _ := netutil.IPAndPortFromAddr(rw.RemoteAddr())

	// Address family metric.
	var family string
	if ip == nil {
		// Unknown.
		family = "0"
	} else if ip.To4() != nil {
		// IPv4.
		family = "1"
	} else {
		// IPv6.
		family = "2"
	}

	// The metric's labels MUST be in the following order:
	// "name", "proto", "network", "addr", "type", "family"
	return vec.WithLabelValues(
		serverInfo.Name,
		serverInfo.Proto.String(),
		string(dnsserver.NetworkFromAddr(rw.LocalAddr())),
		serverInfo.Addr,
		typeToString(req),
		family,
	)
}

// counterWithRequestLabels is a helper method that gets or creates a
// [prometheus.Counter] from the specified *prometheus.CounterVec.  The point of
// this method is to avoid allocating [prometheus.Labels] and instead use the
// WithLabelValues function.  This way extra allocations are avoided, but it is
// sensitive to the labels order.
func counterWithServerLabels(
	serverInfo dnsserver.ServerInfo,
	vec *prometheus.CounterVec,
) (c prometheus.Counter) {
	// The metric's labels MUST be in the following order:
	// "name", "proto", "addr"
	return vec.WithLabelValues(
		serverInfo.Name,
		serverInfo.Proto.String(),
		serverInfo.Addr,
	)
}

// histogramWithServerLabels is a helper method that gets or creates a
// [prometheus.Observer] from the specified *prometheus.HistogramVec.  The point
// of this method is to avoid allocating [prometheus.Labels] and instead use the
// WithLabelValues function.  This way extra allocations are avoided, but it is
// sensitive to the labels order.
func histogramWithServerLabels(
	serverInfo dnsserver.ServerInfo,
	vec *prometheus.HistogramVec,
) (h prometheus.Observer) {
	// The metric's labels MUST be in the following order:
	// "name", "proto", "addr"
	return vec.WithLabelValues(serverInfo.Name, serverInfo.Proto.String(), serverInfo.Addr)
}

// counterWithServerLabelsPlusRCode is a helper method that gets or creates a
// [prometheus.Counter] from the specified *prometheus.CounterVec.  The point of
// this method is to avoid allocating [prometheus.Labels] and instead use the
// WithLabelValues function.  This way extra allocations are avoided, but it is
// sensitive to the labels order.
func counterWithServerLabelsPlusRCode(
	serverInfo dnsserver.ServerInfo,
	rCode string,
	vec *prometheus.CounterVec,
) (c prometheus.Counter) {
	// The metric's labels MUST be in the following order:
	// "name", "proto", "addr", "rcode"
	return vec.WithLabelValues(serverInfo.Name, serverInfo.Proto.String(), serverInfo.Addr, rCode)
}

// setBoolGauge sets gauge to the numeric value corresponding to the val.
func setBoolGauge(gauge prometheus.Gauge, val bool) {
	if val {
		gauge.Set(1)
	} else {
		gauge.Set(0)
	}
}
