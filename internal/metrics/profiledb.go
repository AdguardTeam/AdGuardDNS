package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
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
			Help:      "The number of user devices that were changed or added since the previous sync.",
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
			Help:      "The number of user profiles that were changed or added since the previous sync.",
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

// HandleProfilesUpdate implements the [profilesdb.Metrics] interface for
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

// SetProfilesAndDevicesNum implements the [profilesdb.Metrics] interface for
// *ProfileDB.
func (m *ProfileDB) SetProfilesAndDevicesNum(_ context.Context, profNum, devNum uint) {
	m.profilesCount.Set(float64(profNum))
	m.devicesCount.Set(float64(devNum))
}

// IncrementSyncTimeouts implements the [profilesdb.Metrics] interface for
// *ProfileDB.
func (m *ProfileDB) IncrementSyncTimeouts(_ context.Context, isFullSync bool) {
	if isFullSync {
		m.profilesSyncFullTimeouts.Inc()
	} else {
		m.profilesSyncPartTimeouts.Inc()
	}
}

// IncrementDeleted implements the [profilesdb.Metrics] interface for
// *ProfileDB.
func (m *ProfileDB) IncrementDeleted(_ context.Context) {
	m.profilesDeletedTotal.Inc()
}
