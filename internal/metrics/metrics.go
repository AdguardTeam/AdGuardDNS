// Package metrics contains definitions of most of the prometheus metrics
// that we use in AdGuard DNS.
// TODO(ameshkov): consider not using promauto.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// constants with the namespace and the subsystem names that we use in our
// prometheus metrics.
const (
	namespace = "dns"

	subsystemApplication = "app"
	subsystemBackend     = "backend"
	subsystemBillStat    = "billstat"
	subsystemConsul      = "consul"
	subsystemDNSCheck    = "dnscheck"
	subsystemDNSDB       = "dnsdb"
	subsystemDNSSvc      = "dnssvc"
	subsystemECSCache    = "ecscache"
	subsystemFilter      = "filter"
	subsystemGeoIP       = "geoip"
	subsystemQueryLog    = "querylog"
	subsystemRuleStat    = "rulestat"
	subsystemTLS         = "tls"
)

// SetUpGauge signals that the server has been started.
// We're using a function here to avoid circular dependencies.
func SetUpGauge(version, buildtime, branch, revision, goversion string) {
	upGauge := promauto.NewGauge(
		prometheus.GaugeOpts{
			Name:      "up",
			Namespace: namespace,
			Subsystem: subsystemApplication,
			Help: `A metric with a constant '1' value labeled by ` +
				`version and goversion from which the program was built.`,
			ConstLabels: prometheus.Labels{
				"version":   version,
				"buildtime": buildtime,
				"branch":    branch,
				"revision":  revision,
				"goversion": goversion,
			},
		},
	)

	upGauge.Set(1)
}

// SetStatusGauge is a helper function that automatically checks if there's an
// error and sets the gauge to either 1 (success) or 0 (error).
func SetStatusGauge(gauge prometheus.Gauge, err error) {
	if err == nil {
		gauge.Set(1)
	} else {
		gauge.Set(0)
	}
}

// BoolString returns "1" if cond is true and "0" otherwise.
func BoolString(cond bool) (s string) {
	if cond {
		return "1"
	}

	return "0"
}

// SetAdditionalInfo adds a gauge with extra info labels.  If info is nil,
// SetAdditionalInfo does nothing.
func SetAdditionalInfo(info map[string]string) {
	if info == nil {
		return
	}

	gauge := promauto.NewGauge(
		prometheus.GaugeOpts{
			Name:      "additional_info",
			Namespace: namespace,
			Subsystem: subsystemApplication,
			Help: `A metric with a constant '1' value labeled by additional ` +
				`info provided in configuration`,
			ConstLabels: info,
		},
	)

	gauge.Set(1)
}
