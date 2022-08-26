package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// ConsulAllowlistSize is a gauge with the number of records in the
	// ratelimit allowlist loaded from Consul.
	ConsulAllowlistSize = promauto.NewGauge(prometheus.GaugeOpts{
		Subsystem: subsystemConsul,
		Namespace: namespace,
		Name:      "allowlist_size",
		Help:      "Size of the ratelimit allowlist loaded from Consul.",
	})
	// ConsulAllowlistUpdateStatus is a gauge with the status of the last
	// ratelimit allowlist update.  1 means success.
	ConsulAllowlistUpdateStatus = promauto.NewGauge(prometheus.GaugeOpts{
		Subsystem: subsystemConsul,
		Namespace: namespace,
		Name:      "allowlist_update_status",
		Help:      "Status of the last ratelimit allowlist update. 1 means success.",
	})
	// ConsulAllowlistUpdateTime is a gauge with the timestamp of the last
	// ratelimit allowlist update.
	ConsulAllowlistUpdateTime = promauto.NewGauge(prometheus.GaugeOpts{
		Subsystem: subsystemConsul,
		Namespace: namespace,
		Name:      "allowlist_update_timestamp",
		Help:      "Timestamp of the last ratelimit allowlist update.",
	})
)
