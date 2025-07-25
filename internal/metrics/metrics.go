// Package metrics contains definitions of most of the prometheus metrics that
// we use in AdGuard DNS.
//
// NOTE:  Prefer to not import any packages from the current module here,
// because a lot of packages import metrics, and so import cycles may happen.
package metrics

import (
	"cmp"
	"fmt"
	"os"

	"github.com/prometheus/client_golang/prometheus"
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
// avoid circular dependencies.  reg must not be nil.
func SetUpGauge(
	reg prometheus.Registerer,
	version string,
	branch string,
	commitTime string,
	revision string,
	goVersion string,
) (err error) {
	upGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:      "up",
		Namespace: namespace,
		Subsystem: subsystemApplication,
		Help:      `A metric with a constant '1' value labeled by the build information.`,
		ConstLabels: prometheus.Labels{
			"branch":     branch,
			"committime": commitTime,
			"goversion":  goVersion,
			"revision":   revision,
			"version":    version,
		},
	})
	err = reg.Register(upGauge)
	if err != nil {
		return fmt.Errorf("registering up metric: %w", err)
	}

	upGauge.Set(1)

	return nil
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
// SetAdditionalInfo does nothing.  reg must not be nil.
func SetAdditionalInfo(reg prometheus.Registerer, info map[string]string) (err error) {
	if info == nil {
		return
	}

	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:      "additional_info",
		Namespace: namespace,
		Subsystem: subsystemApplication,
		Help: `A metric with a constant '1' value labeled by additional ` +
			`info provided in configuration`,
		ConstLabels: info,
	})

	err = reg.Register(gauge)
	if err != nil {
		return fmt.Errorf("registering additional_info metric: %w", err)
	}

	gauge.Set(1)

	return nil
}

// Namespace returns the namespace that we use in our prometheus metrics.
func Namespace() (ns string) {
	return namespace
}
