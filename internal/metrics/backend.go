package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// DevicesCountGauge is a gauge with the total number of user devices loaded
// from the backend.
var DevicesCountGauge = promauto.NewGauge(prometheus.GaugeOpts{
	Name:      "devices_total",
	Subsystem: subsystemBackend,
	Namespace: namespace,
	Help:      "The total number of user devices loaded from the backend.",
})

// DevicesNewCountGauge is a gauge with the number of user devices downloaded
// during the last sync.
var DevicesNewCountGauge = promauto.NewGauge(prometheus.GaugeOpts{
	Name:      "devices_newly_synced_total",
	Subsystem: subsystemBackend,
	Namespace: namespace,
	Help:      "The number of user devices that were changed or added since the previous sync.",
})

// DevicesInvalidTotal is a gauge with the number of invalid user devices loaded
// from the backend.
var DevicesInvalidTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name:      "devices_invalid_total",
	Subsystem: subsystemBackend,
	Namespace: namespace,
	Help:      "The total number of invalid user devices loaded from the backend.",
})

// ProfilesCountGauge is a gauge with the total number of user profiles loaded
// from the backend.
var ProfilesCountGauge = promauto.NewGauge(prometheus.GaugeOpts{
	Name:      "profiles_total",
	Subsystem: subsystemBackend,
	Namespace: namespace,
	Help:      "The total number of user profiles loaded from the backend.",
})

// ProfilesNewCountGauge is a gauge with the number of user profiles downloaded
// during the last sync.
var ProfilesNewCountGauge = promauto.NewGauge(prometheus.GaugeOpts{
	Name:      "profiles_newly_synced_total",
	Subsystem: subsystemBackend,
	Namespace: namespace,
	Help:      "The number of user profiles that were changed or added since the previous sync.",
})

// ProfilesSyncTime is a gauge with the timestamp when the profiles were
// synced last time.
var ProfilesSyncTime = promauto.NewGauge(prometheus.GaugeOpts{
	Name:      "profiles_sync_timestamp",
	Subsystem: subsystemBackend,
	Namespace: namespace,
	Help:      "The time when the user profiles were synced last time.",
})

// ProfilesSyncStatus is a gauge with the profiles sync status.  Set it to 1
// if the sync was successful.  Otherwise, set it to 0.
var ProfilesSyncStatus = promauto.NewGauge(prometheus.GaugeOpts{
	Name:      "profiles_sync_status",
	Subsystem: subsystemBackend,
	Namespace: namespace,
	Help:      "Status of the last profiles sync. 1 is okay, 0 means there was an error",
})

// ProfilesSyncDuration is a histogram with the duration of a profiles sync.
var ProfilesSyncDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:      "profiles_sync_duration_seconds",
	Subsystem: subsystemBackend,
	Namespace: namespace,
	Help:      "Time elapsed on syncing user profiles with the backend.",
	// Profiles sync may take some time since the list of users may be
	// massive. This is why the buckets go up to 240 seconds.
	Buckets: []float64{0.01, 0.1, 1, 5, 10, 30, 60, 120, 240},
})

// ProfilesFullSyncDuration is a gauge with the duration of the last full sync.
// It is a gauge because full syncs are not expected to be common.
var ProfilesFullSyncDuration = promauto.NewGauge(prometheus.GaugeOpts{
	Name:      "profiles_full_sync_duration_seconds",
	Subsystem: subsystemBackend,
	Namespace: namespace,
	Help:      "Time elapsed on fully syncing user profiles with the backend, in seconds.",
})

// GRPCAvgProfileRecvDuration is a histogram with the average duration of a
// receive of a single profile during a backend call.
var GRPCAvgProfileRecvDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:      "grpc_avg_profile_recv_duration_seconds",
	Subsystem: subsystemBackend,
	Namespace: namespace,
	Help: "The average duration of a receive of a profile during a call to the backend, " +
		"in seconds.",
	Buckets: []float64{0.000_001, 0.000_010, 0.000_100, 0.001},
})

// GRPCAvgProfileDecDuration is a histogram with the average duration of
// decoding a single profile during a backend call.
var GRPCAvgProfileDecDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:      "grpc_avg_profile_dec_duration_seconds",
	Subsystem: subsystemBackend,
	Namespace: namespace,
	Help: "The average duration of decoding one profile during a call to the backend, " +
		"in seconds.",
	Buckets: []float64{0.000_001, 0.000_01, 0.000_1, 0.001},
})

var (
	// profilesSyncTimeouts is a gauge with the total number of timeout errors
	// occurred during profiles sync, either full or partial.
	profilesSyncTimeouts = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "profiles_sync_timeouts_total",
		Namespace: namespace,
		Subsystem: subsystemBackend,
		Help:      "The total number of timeout errors during profiles sync.",
	}, []string{"is_full_sync"})

	// ProfilesSyncFullTimeouts is a gauge with the total number of timeout
	// errors occurred during full profiles sync.
	ProfilesSyncFullTimeouts = profilesSyncTimeouts.With(prometheus.Labels{
		"is_full_sync": "1",
	})

	// ProfilesSyncPartTimeouts is a gauge with the total number of timeout
	// errors occurred during partial profiles sync.
	ProfilesSyncPartTimeouts = profilesSyncTimeouts.With(prometheus.Labels{
		"is_full_sync": "0",
	})
)
