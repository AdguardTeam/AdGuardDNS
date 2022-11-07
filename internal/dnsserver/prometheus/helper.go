package prometheus

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

// requestLabels creates labels for the specified DNS request.
func requestLabels(
	ctx context.Context,
	req *dns.Msg,
	rw dnsserver.ResponseWriter,
) prometheus.Labels {
	// Base labels with general server information (name, addr, proto).
	labels := baseLabels(ctx)

	// DNS query type (only use those we're interested in).
	labels["type"] = typeToString(req)

	// Network type (tcp or udp).
	labels["network"] = string(dnsserver.NetworkFromAddr(rw.LocalAddr()))

	// Address family.
	ip, _ := netutil.IPAndPortFromAddr(rw.RemoteAddr())
	if ip == nil {
		labels["family"] = "0"
	} else if ip.To4() != nil {
		labels["family"] = "1"
	} else {
		labels["family"] = "2"
	}

	return labels
}

// baseLabels creates base prom labels that we have in every counter.
func baseLabels(ctx context.Context) prometheus.Labels {
	serverInfo := dnsserver.MustServerInfoFromContext(ctx)

	return prometheus.Labels{
		"name":  serverInfo.Name,
		"addr":  serverInfo.Addr,
		"proto": serverInfo.Proto.String(),
	}
}

// setBoolGauge sets gauge to the numeric value corresponding to the val.
func setBoolGauge(gauge prometheus.Gauge, val bool) {
	if val {
		gauge.Set(1)
	} else {
		gauge.Set(0)
	}
}
