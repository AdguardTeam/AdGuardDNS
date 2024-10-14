// Package metrics contains definitions of most of the prometheus metrics that
// we use in AdGuard DNS.
//
// NOTE:  Prefer to not import any packages from the current module here,
// because a lot of packages import metrics, and so import cycles may happen.
//
// TODO(a.garipov):  Do not use promauto.
package metrics

import (
	"cmp"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// namespace is the configurable namespace that we use in our prometheus
// metrics.
//
// TODO(a.garipov):  Refactor to not require any global state.
var namespace = cmp.Or(os.Getenv("METRICS_NAMESPACE"), "dns")

// Constants with the subsystem names that we use in our prometheus metrics.
const (
	subsystemAccess       = "access"
	subsystemApplication  = "app"
	subsystemBackend      = "backend"
	subsystemBillStat     = "billstat"
	subsystemBindToDevice = "bindtodevice"
	subsystemConnLimiter  = "connlimiter"
	subsystemConsul       = "consul"
	subsystemDNSCheck     = "dnscheck"
	subsystemDNSDB        = "dnsdb"
	subsystemDNSMsg       = "dnsmsg"
	subsystemDNSSvc       = "dnssvc"
	subsystemECSCache     = "ecscache"
	subsystemFilter       = "filter"
	subsystemGeoIP        = "geoip"
	subsystemQueryLog     = "querylog"
	subsystemResearch     = "research"
	subsystemRuleStat     = "rulestat"
	subsystemTLS          = "tls"
	subsystemWebSvc       = "websvc"
)

// Constants that should be kept in sync with ones in package prometheus in
// module dnsserver.
const (
	subsystemRateLimit = "ratelimit"
)

const (
	// dontStoreLabel is a label that signals that the metric should not be
	// stored in the long-term storage.
	dontStoreLabel = "do_not_store_metric"

	// dontStoreLabelValue is a positive value of the [dontStoreLabel] label to
	// avoid calling [BoolString] every time.
	dontStoreLabelValue = "1"
)

// SetUpGauge signals that the server has been started.  Use a function here to
// avoid circular dependencies.
func SetUpGauge(version, commitTime, branch, revision, goversion string) {
	upGauge := promauto.NewGauge(
		prometheus.GaugeOpts{
			Name:      "up",
			Namespace: namespace,
			Subsystem: subsystemApplication,
			Help: `A metric with a constant '1' value labeled by ` +
				`version and goversion from which the program was built. ` +
				`NOTE: buildtime is actually the time of the commit.`,
			ConstLabels: prometheus.Labels{
				"version": version,
				// TODO(a.garipov):  Consider renaming the metric.
				"buildtime": commitTime,
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

// IncrementCond increments trueCounter if cond is true and falseCounter
// otherwise.
func IncrementCond(cond bool, trueCounter, falseCounter prometheus.Counter) {
	if cond {
		trueCounter.Inc()
	} else {
		falseCounter.Inc()
	}
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

// Namespace returns the namespace that we use in our prometheus metrics.
func Namespace() (ns string) {
	return namespace
}
