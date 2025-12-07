package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/c2h5oh/datasize"
	"github.com/prometheus/client_golang/prometheus"
)

// UpdateMetrics is an alias for a structure that contains the information about
// a user profiles update operation.
//
// See [profiledb.UpdateMetrics].
type UpdateMetrics = struct {
	Duration    time.Duration
	ProfilesNum uint
	DevicesNum  uint
	IsSuccess   bool
	IsFullSync  bool
}

// ProfileDB is the Prometheus-based implementation of the [profiledb.Metrics]
// interface.
type ProfileDB struct {
	// devicesCount is a gauge with the total number of user devices loaded from
	// the backend.
	devicesCount prometheus.Gauge

	// devicesNewCount is a gauge with the number of user devices downloaded
	// during the last sync.
	devicesNewCount prometheus.Gauge

	// fileCacheSize is a gauge with the size of the last successfully
	// synchronized cache file.
	fileCacheSize prometheus.Gauge

	// fileCacheSyncTime is a gauge with the timestamp of the last successful
	// cache file synchronization.
	fileCacheSyncTime prometheus.Gauge

	// fileCacheStoreDuration is a histogram with the duration of storing the
	// file cache to disk.
	fileCacheStoreDuration prometheus.Histogram

	// profilesCount is a gauge with the total number of user profiles loaded
	// from the backend.
	profilesCount prometheus.Gauge

	// profilesNewCount is a gauge with the number of user profiles downloaded
	// during the last sync.
	profilesNewCount prometheus.Gauge

	// profilesDeletedTotal is a counter with the total number of user profiles
	// marked as deleted which have been loaded from the backend.
	//
	// TODO(d.kolyshev): Add a metric for deleted devices.
	profilesDeletedTotal prometheus.Counter

	// profilesSyncTime is a gauge with the timestamp when the profiles were
	// synced last time.
	profilesSyncTime prometheus.Gauge

	// profilesSyncStatus is a gauge with the profiles sync status.  Set it to 1
	// if the sync was successful.  Otherwise, set it to 0.
	profilesSyncStatus prometheus.Gauge

	// profilesSyncDuration is a histogram with the duration of a profiles sync.
	profilesSyncDuration prometheus.Histogram

	// profilesFullSyncDuration is a gauge with the duration of the last full
	// sync.  It is a gauge because full syncs are not expected to be common.
	profilesFullSyncDuration prometheus.Gauge

	// profilesSyncFullTimeouts is a gauge with the total number of timeout
	// errors occurred during full profiles sync.
	profilesSyncFullTimeouts prometheus.Gauge

	// profilesSyncPartTimeouts is a gauge with the total number of timeout
	// errors occurred during partial profiles sync.
	profilesSyncPartTimeouts prometheus.Gauge
}

// NewProfileDB registers the user profiles metrics in reg and returns a
// properly initialized [ProfileDB].
func NewProfileDB(namespace string, reg prometheus.Registerer) (m *ProfileDB, err error) {
	const (
		devicesCount             = "devices_total"
		devicesNewCount          = "devices_newly_synced_total"
		fileCacheSize            = "file_cache_size_bytes"
		fileCacheStoreDuration   = "file_cache_store_duration_seconds"
		fileCacheSyncTime        = "file_cache_sync_timestamp"
		profilesCount            = "profiles_total"
		profilesNewCount         = "profiles_newly_synced_total"
		profilesDeletedTotal     = "profiles_deleted_total"
		profilesSyncTime         = "profiles_sync_timestamp"
		profilesSyncStatus       = "profiles_sync_status"
		profilesSyncDuration     = "profiles_sync_duration_seconds"
		profilesFullSyncDuration = "profiles_full_sync_duration_seconds"
		profilesSyncTimeouts     = "profiles_sync_timeouts_total"
	)

	// profilesSyncTimeoutsGaugeVec is a gauge with the total number of timeout
	// errors occurred during profiles sync, either full or partial.
	profilesSyncTimeoutsGaugeVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:      profilesSyncTimeouts,
		Namespace: namespace,
		Subsystem: subsystemBackend,
		Help:      "The total number of timeout errors during profiles sync.",
	}, []string{"is_full_sync"})

	m = &ProfileDB{
		devicesCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      devicesCount,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "The total number of user devices loaded from the backend.",
		}),
		devicesNewCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      devicesNewCount,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help: "The number of user devices that were changed or added since " +
				"the previous sync.",
		}),
		fileCacheSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      fileCacheSize,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "The size of the last successfully synchronized cache file.",
		}),
		fileCacheStoreDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:      fileCacheStoreDuration,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "Time elapsed on storing file cache to disk, in seconds.",
			Buckets:   []float64{0.001, 0.01, 0.1, 0.5, 1, 2, 5},
		}),
		fileCacheSyncTime: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      fileCacheSyncTime,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "The time when the file cache was synced last time.",
		}),
		profilesCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      profilesCount,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "The total number of user profiles loaded from the backend.",
		}),
		profilesNewCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      profilesNewCount,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help: "The number of user profiles that were changed or added since " +
				"the previous sync.",
		}),
		profilesDeletedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:      profilesDeletedTotal,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "The total number of deleted user profiles loaded from the backend.",
		}),
		profilesSyncTime: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      profilesSyncTime,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "The time when the user profiles were synced last time.",
		}),
		profilesSyncStatus: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      profilesSyncStatus,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "Status of the last profiles sync. 1 is okay, 0 means there was an error",
		}),
		profilesSyncDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:      profilesSyncDuration,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "Time elapsed on syncing user profiles with the backend.",
			// Profiles sync may take some time since the list of users may be
			// massive. This is why the buckets go up to 240 seconds.
			Buckets: []float64{0.01, 0.1, 1, 5, 10, 30, 60, 120, 240},
		}),
		profilesFullSyncDuration: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      profilesFullSyncDuration,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "Time elapsed on fully syncing user profiles with the backend, in seconds.",
		}),
		profilesSyncFullTimeouts: profilesSyncTimeoutsGaugeVec.With(prometheus.Labels{
			"is_full_sync": "1",
		}),
		profilesSyncPartTimeouts: profilesSyncTimeoutsGaugeVec.With(prometheus.Labels{
			"is_full_sync": "0",
		}),
	}

	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   fileCacheSize,
		Value: m.fileCacheSize,
	}, {
		Key:   fileCacheStoreDuration,
		Value: m.fileCacheStoreDuration,
	}, {
		Key:   fileCacheSyncTime,
		Value: m.fileCacheSyncTime,
	}, {
		Key:   devicesCount,
		Value: m.devicesCount,
	}, {
		Key:   devicesNewCount,
		Value: m.devicesNewCount,
	}, {
		Key:   profilesCount,
		Value: m.profilesCount,
	}, {
		Key:   profilesNewCount,
		Value: m.profilesNewCount,
	}, {
		Key:   profilesDeletedTotal,
		Value: m.profilesDeletedTotal,
	}, {
		Key:   profilesSyncTime,
		Value: m.profilesSyncTime,
	}, {
		Key:   profilesSyncStatus,
		Value: m.profilesSyncStatus,
	}, {
		Key:   profilesSyncDuration,
		Value: m.profilesSyncDuration,
	}, {
		Key:   profilesFullSyncDuration,
		Value: m.profilesFullSyncDuration,
	}, {
		Key:   profilesSyncTimeouts,
		Value: profilesSyncTimeoutsGaugeVec,
	}}

	var errs []error
	for _, c := range collectors {
		err = reg.Register(c.Value)
		if err != nil {
			errs = append(errs, fmt.Errorf("registering metrics %q: %w", c.Key, err))
		}
	}

	if err = errors.Join(errs...); err != nil {
		return nil, err
	}

	return m, nil
}

// HandleProfilesUpdate implements the [profiledb.Metrics] interface for
// *ProfileDB.
func (m *ProfileDB) HandleProfilesUpdate(_ context.Context, u *UpdateMetrics) {
	m.profilesSyncTime.SetToCurrentTime()
	m.profilesNewCount.Set(float64(u.ProfilesNum))
	m.devicesNewCount.Set(float64(u.DevicesNum))

	if u.IsSuccess {
		m.profilesSyncStatus.Set(1)
	} else {
		m.profilesSyncStatus.Set(0)
	}

	dur := u.Duration.Seconds()
	m.profilesSyncDuration.Observe(dur)
	if u.IsFullSync {
		m.profilesFullSyncDuration.Set(dur)
	}
}

// SetProfilesAndDevicesNum implements the [profiledb.Metrics] interface for
// *ProfileDB.
func (m *ProfileDB) SetProfilesAndDevicesNum(_ context.Context, profNum, devNum uint) {
	m.profilesCount.Set(float64(profNum))
	m.devicesCount.Set(float64(devNum))
}

// IncrementSyncTimeouts implements the [profiledb.Metrics] interface for
// *ProfileDB.
func (m *ProfileDB) IncrementSyncTimeouts(_ context.Context, isFullSync bool) {
	if isFullSync {
		m.profilesSyncFullTimeouts.Inc()
	} else {
		m.profilesSyncPartTimeouts.Inc()
	}
}

// IncrementDeleted implements the [profiledb.Metrics] interface for *ProfileDB.
func (m *ProfileDB) IncrementDeleted(_ context.Context) {
	m.profilesDeletedTotal.Inc()
}

// SetLastFileCacheSyncTime implements the [profiledb.Metrics] interface for
// *ProfileDB.
func (m *ProfileDB) SetLastFileCacheSyncTime(_ context.Context, t time.Time) {
	m.fileCacheSyncTime.Set(float64(t.Unix()))
}

// SetFileCacheSize implements the [profiledb.Metrics] interface for *ProfileDB.
func (m *ProfileDB) SetFileCacheSize(_ context.Context, size datasize.ByteSize) {
	m.fileCacheSize.Set(float64(size))
}

// ObserveFileCacheStoreDuration records the duration of storing file cache to disk.
func (m *ProfileDB) ObserveFileCacheStoreDuration(_ context.Context, d time.Duration) {
	m.fileCacheStoreDuration.Observe(d.Seconds())
}

// BackendProfileDB is the Prometheus-based implementation of the
// [backendpb.ProfileDBMetrics] interface.
type BackendProfileDB struct {
	// devicesInvalidTotal is a gauge with the number of invalid user devices
	// loaded from the backend.
	devicesInvalidTotal prometheus.Counter

	// grpcAvgProfileRecvDuration is a histogram with the average duration of a
	// receive of a single profile during a backend call.
	grpcAvgProfileRecvDuration prometheus.Histogram

	// grpcAvgProfileDecDuration is a histogram with the average duration of
	// decoding a single profile during a backend call.
	grpcAvgProfileDecDuration prometheus.Histogram
}

// NewBackendProfileDB registers the protobuf errors metrics in reg and returns
// a properly initialized [BackendProfileDB].
func NewBackendProfileDB(
	namespace string,
	reg prometheus.Registerer,
) (m *BackendProfileDB, err error) {
	const (
		devicesInvalidTotal        = "devices_invalid_total"
		grpcAvgProfileRecvDuration = "grpc_avg_profile_recv_duration_seconds"
		grpcAvgProfileDecDuration  = "grpc_avg_profile_dec_duration_seconds"
	)

	m = &BackendProfileDB{
		devicesInvalidTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:      devicesInvalidTotal,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help:      "The total number of invalid user devices loaded from the backend.",
		}),
		grpcAvgProfileRecvDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:      grpcAvgProfileRecvDuration,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help: "The average duration of a receive of a profile during a call to the backend, " +
				"in seconds.",
			Buckets: []float64{0.000_001, 0.000_010, 0.000_100, 0.001},
		}),
		grpcAvgProfileDecDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:      grpcAvgProfileDecDuration,
			Subsystem: subsystemBackend,
			Namespace: namespace,
			Help: "The average duration of decoding one profile during a call to the backend, " +
				"in seconds.",
			Buckets: []float64{0.000_001, 0.000_01, 0.000_1, 0.001},
		}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   devicesInvalidTotal,
		Value: m.devicesInvalidTotal,
	}, {
		Key:   grpcAvgProfileRecvDuration,
		Value: m.grpcAvgProfileRecvDuration,
	}, {
		Key:   grpcAvgProfileDecDuration,
		Value: m.grpcAvgProfileDecDuration,
	}}

	for _, c := range collectors {
		err = reg.Register(c.Value)
		if err != nil {
			errs = append(errs, fmt.Errorf("registering metrics %q: %w", c.Key, err))
		}
	}

	if err = errors.Join(errs...); err != nil {
		return nil, err
	}

	return m, nil
}

// IncrementInvalidDevicesCount implements the [backendpb.ProfileDBMetrics]
// interface for BackendProfileDB.
func (m *BackendProfileDB) IncrementInvalidDevicesCount(_ context.Context) {
	m.devicesInvalidTotal.Inc()
}

// UpdateStats implements the [backendpb.ProfileDBMetrics] interface for
// BackendProfileDB.
func (m *BackendProfileDB) UpdateStats(_ context.Context, avgRecv, avgDec time.Duration) {
	m.grpcAvgProfileRecvDuration.Observe(avgRecv.Seconds())
	m.grpcAvgProfileDecDuration.Observe(avgDec.Seconds())
}
