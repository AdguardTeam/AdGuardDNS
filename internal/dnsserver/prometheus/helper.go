package prometheus

import (
	"context"
	"net"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

// reqLabelMetricKey contains the information for a request label.
type reqLabelMetricKey struct {
	network string
	qType   string
	family  string
	srvInfo dnsserver.ServerInfo
}

// newReqLabelMetricKey returns a new metric key from the given data.
func newReqLabelMetricKey(
	ctx context.Context,
	req *dns.Msg,
	rw dnsserver.ResponseWriter,
) (k reqLabelMetricKey) {
	return reqLabelMetricKey{
		network: string(dnsserver.NetworkFromAddr(rw.LocalAddr())),
		qType:   typeToString(req),
		family:  raddrToFamily(rw.RemoteAddr()),
		srvInfo: dnsserver.MustServerInfoFromContext(ctx),
	}
}

// withLabelValues returns a counter with the given arguments in the correct
// order.
func (k reqLabelMetricKey) withLabelValues(vec *prometheus.CounterVec) (c prometheus.Counter) {
	// The labels must be in the following order:
	//   1. server name;
	//   2. server protocol;
	//   3. server socket network ("tcp"/"udp");
	//   4. server addr;
	//   5. question type (see [typeToString]);
	//   6. IP family (see [raddrToFamily]).
	return vec.WithLabelValues(
		k.srvInfo.Name,
		k.srvInfo.Proto.String(),
		k.network,
		k.srvInfo.Addr,
		k.qType,
		k.family,
	)
}

// prometheusVector is the interface for vectors of counters, histograms, etc.
type prometheusVector[T any] interface {
	WithLabelValues(labelValues ...string) (m T)
}

// withSrvInfoLabelValues returns a metric with the server info data in the
// correct order.
func withSrvInfoLabelValues[T any](
	vec prometheusVector[T],
	srvInfo dnsserver.ServerInfo,
) (m T) {
	// The labels must be in the following order:
	//   1. server name;
	//   2. server protocol;
	//   3. server addr;
	return vec.WithLabelValues(
		srvInfo.Name,
		srvInfo.Proto.String(),
		srvInfo.Addr,
	)
}

// raddrToFamily returns a family metric value for raddr.
// The values are:
//
//  0. Unknown.
//  1. IPv4.
//  2. IPv6.
func raddrToFamily(raddr net.Addr) (family string) {
	ip := netutil.NetAddrToAddrPort(raddr).Addr()

	if !ip.IsValid() {
		return "0"
	} else if ip.Is4() {
		return "1"
	}

	return "2"
}

// setBoolGauge sets gauge to the numeric value corresponding to the val.
func setBoolGauge(gauge prometheus.Gauge, val bool) {
	if val {
		gauge.Set(1)
	} else {
		gauge.Set(0)
	}
}
