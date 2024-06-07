// Package profiledb defines interfaces for databases of user profiles.
package profiledb

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/filecachepb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
)

// Interface is the local database of user profiles and devices.
type Interface interface {
	// ProfileByDeviceID returns the profile and the device identified by id.
	ProfileByDeviceID(
		ctx context.Context,
		id agd.DeviceID,
	) (p *agd.Profile, d *agd.Device, err error)

	// ProfileByDedicatedIP returns the profile and the device identified by its
	// dedicated DNS server IP address.
	ProfileByDedicatedIP(
		ctx context.Context,
		ip netip.Addr,
	) (p *agd.Profile, d *agd.Device, err error)

	// ProfileByLinkedIP returns the profile and the device identified by its
	// linked IP address.
	ProfileByLinkedIP(ctx context.Context, ip netip.Addr) (p *agd.Profile, d *agd.Device, err error)
}

// type check
var _ Interface = (*Disabled)(nil)

// Disabled is a profile database that panics on any call.
type Disabled struct{}

// profilesDBUnexpectedCall is a panic message template for lookup methods when
// profiles database is disabled.
const profilesDBUnexpectedCall string = "profiles db: unexpected call to %s"

// ProfileByDeviceID implements the [Interface] interface for *Disabled.
func (d *Disabled) ProfileByDeviceID(
	_ context.Context,
	_ agd.DeviceID,
) (_ *agd.Profile, _ *agd.Device, _ error) {
	panic(fmt.Errorf(profilesDBUnexpectedCall, "ProfileByDeviceID"))
}

// ProfileByDedicatedIP implements the [Interface] interface for *Disabled.
func (d *Disabled) ProfileByDedicatedIP(
	_ context.Context, _ netip.Addr,
) (_ *agd.Profile, _ *agd.Device, _ error) {
	panic(fmt.Errorf(profilesDBUnexpectedCall, "ProfileByDedicatedIP"))
}

// ProfileByLinkedIP implements the [Interface] interface for *Disabled.
func (d *Disabled) ProfileByLinkedIP(
	_ context.Context,
	_ netip.Addr,
) (_ *agd.Profile, _ *agd.Device, _ error) {
	panic(fmt.Errorf(profilesDBUnexpectedCall, "ProfileByLinkedIP"))
}

// Config represents the profile database configuration.
type Config struct {
	// Storage returns the data for this profile DB.
	Storage Storage

	// ErrColl is used to collect errors during refreshes.
	ErrColl errcoll.Interface

	// CacheFilePath is the path to the profile cache file.  If cacheFilePath is
	// the string "none", filesystem cache is disabled.
	CacheFilePath string

	// FullSyncIvl is the interval between two full synchronizations with the
	// storage.
	FullSyncIvl time.Duration

	// FullSyncRetryIvl is the interval between two retries of full
	// synchronizations with the storage.
	FullSyncRetryIvl time.Duration

	// InitialTimeout is the timeout for initial refresh.
	InitialTimeout time.Duration
}

// Default is the default in-memory implementation of the [Interface] interface
// that can refresh itself from the provided storage.
type Default struct {
	// mapsMu protects the profiles, devices, deviceIDToProfileID,
	// linkedIPToDeviceID, and dedicatedIPToDeviceID maps.
	mapsMu *sync.RWMutex

	// refreshMu serializes Refresh calls and access to all values used inside
	// of it.
	refreshMu *sync.Mutex

	// errColl is used to collect errors during refreshes.
	errColl errcoll.Interface

	// cache is the filesystem-cache storage used by this profile database.
	cache internal.FileCacheStorage

	// storage returns the data for this profile DB.
	storage Storage

	// profiles maps profile IDs to profile records.
	profiles map[agd.ProfileID]*agd.Profile

	// devices maps device IDs to device records.
	devices map[agd.DeviceID]*agd.Device

	// deviceIDToProfileID maps device IDs to the ID of their profile.
	deviceIDToProfileID map[agd.DeviceID]agd.ProfileID

	// linkedIPToDeviceID maps linked IP addresses to the IDs of their devices.
	linkedIPToDeviceID map[netip.Addr]agd.DeviceID

	// dedicatedIPToDeviceID maps dedicated IP addresses to the IDs of their
	// devices.
	dedicatedIPToDeviceID map[netip.Addr]agd.DeviceID

	// syncTime is the time of the last synchronization point.  It is received
	// from the storage during a refresh and is then used in consecutive
	// requests to the storage, unless it's a full synchronization.
	syncTime time.Time

	// lastFullSync is the time of the last successful full synchronization.
	lastFullSync time.Time

	// lastFullSyncError is the time of the last unsuccessful attempt at a full
	// synchronization.  If the last full synchronization was successful, this
	// field is time.Time{}.
	lastFullSyncError time.Time

	// fullSyncIvl is the interval between two full synchronizations with the
	// storage.
	fullSyncIvl time.Duration

	// fullSyncRetryIvl is the interval between two retries of full
	// synchronizations with the storage.
	fullSyncRetryIvl time.Duration
}

// New returns a new default in-memory profile database with a filesystem cache.
// The initial refresh is performed immediately with the given timeout, beyond
// which an empty profiledb is returned.  If cacheFilePath is the string "none",
// filesystem cache is disabled.  db is never nil.
func New(conf *Config) (db *Default, err error) {
	var cacheStorage internal.FileCacheStorage
	if conf.CacheFilePath == "none" {
		cacheStorage = internal.EmptyFileCacheStorage{}
	} else if ext := filepath.Ext(conf.CacheFilePath); ext == ".pb" {
		cacheStorage = filecachepb.New(conf.CacheFilePath)
	} else {
		return nil, fmt.Errorf("file %q is not protobuf", conf.CacheFilePath)
	}

	db = &Default{
		mapsMu:                &sync.RWMutex{},
		refreshMu:             &sync.Mutex{},
		errColl:               conf.ErrColl,
		cache:                 cacheStorage,
		storage:               conf.Storage,
		syncTime:              time.Time{},
		lastFullSync:          time.Time{},
		lastFullSyncError:     time.Time{},
		profiles:              make(map[agd.ProfileID]*agd.Profile),
		devices:               make(map[agd.DeviceID]*agd.Device),
		deviceIDToProfileID:   make(map[agd.DeviceID]agd.ProfileID),
		linkedIPToDeviceID:    make(map[netip.Addr]agd.DeviceID),
		dedicatedIPToDeviceID: make(map[netip.Addr]agd.DeviceID),
		fullSyncIvl:           conf.FullSyncIvl,
		fullSyncRetryIvl:      conf.FullSyncRetryIvl,
	}

	err = db.loadFileCache()
	if err != nil {
		log.Error("profiledb: fs cache: loading: %s", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), conf.InitialTimeout)
	defer cancel()

	log.Info("profiledb: initial refresh")

	err = db.Refresh(ctx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Info("profiledb: warning: initial refresh timeout: %s", err)

			return db, nil
		}

		return nil, fmt.Errorf("initial refresh: %w", err)
	}

	log.Info("profiledb: initial refresh succeeded")

	return db, nil
}

// type check
var _ agdservice.Refresher = (*Default)(nil)

// Refresh implements the [agdservice.Refresher] interface for *Default.  It
// updates the internal maps and the synchronization time using the data it
// receives from the storage.
//
// TODO(a.garipov): Consider splitting the full refresh logic into a separate
// method.
func (db *Default) Refresh(ctx context.Context) (err error) {
	// TODO(a.garipov):  Use slog.
	log.Debug("profiledb_refresh: started")
	defer log.Debug("profiledb_refresh: finished")

	sinceLastAttempt, isFullSync := db.needsFullSync()

	var profNum, devNum int
	startTime := time.Now()
	defer func() {
		metrics.ProfilesSyncTime.SetToCurrentTime()
		metrics.ProfilesNewCountGauge.Set(float64(profNum))
		metrics.DevicesNewCountGauge.Set(float64(devNum))
		metrics.SetStatusGauge(metrics.ProfilesSyncStatus, err)

		dur := time.Since(startTime).Seconds()
		metrics.ProfilesSyncDuration.Observe(dur)
		if isFullSync {
			metrics.ProfilesFullSyncDuration.Set(dur)
		}

		if err != nil {
			errcoll.Collectf(ctx, db.errColl, "profiledb_refresh: %w", err)
		}
	}()

	reqID := agd.NewRequestID()
	ctx = agd.WithRequestID(ctx, reqID)

	defer func() { err = errors.Annotate(err, "req %s: %w", reqID) }()

	db.refreshMu.Lock()
	defer db.refreshMu.Unlock()

	defer func() {
		metrics.ProfilesCountGauge.Set(float64(len(db.profiles)))
		metrics.DevicesCountGauge.Set(float64(len(db.devices)))
	}()

	resp, err := db.fetchProfiles(ctx, sinceLastAttempt, isFullSync)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	profiles := resp.Profiles
	devices := resp.Devices
	db.setProfiles(profiles, devices, isFullSync)

	profNum = len(profiles)
	devNum = len(devices)
	log.Debug("profiledb: req %s: got %d profiles with %d devices", reqID, profNum, devNum)

	db.syncTime = resp.SyncTime
	if isFullSync {
		db.lastFullSync = time.Now()
		db.lastFullSyncError = time.Time{}

		err = db.cache.Store(&internal.FileCache{
			SyncTime: resp.SyncTime,
			Profiles: profiles,
			Devices:  devices,
			Version:  internal.FileCacheVersion,
		})
		if err != nil {
			return fmt.Errorf("saving cache: %w", err)
		}
	}

	return nil
}

// fetchProfiles fetches the profiles and devices from the storage.  It returns
// the response and the error, if any.  If isFullSync is true, the last full
// synchronization error time is updated on error.  It must only be called under
// the refreshMu lock.
func (db *Default) fetchProfiles(
	ctx context.Context,
	sinceLastAttempt time.Duration,
	isFullSync bool,
) (sr *StorageResponse, err error) {
	syncTime := db.syncTime
	if isFullSync {
		log.Info("profiledb: full sync, %s since last attempt", sinceLastAttempt)

		syncTime = time.Time{}
	}

	sr, err = db.storage.Profiles(ctx, &StorageRequest{
		SyncTime: syncTime,
	})
	if err == nil {
		return sr, nil
	}

	if isFullSync {
		db.lastFullSyncError = time.Now()
	}

	if errors.Is(err, context.DeadlineExceeded) {
		metrics.IncrementCond(
			isFullSync,
			metrics.ProfilesSyncFullTimeouts,
			metrics.ProfilesSyncPartTimeouts,
		)
	}

	return nil, fmt.Errorf("updating profiles: %w", err)
}

// needsFullSync determines if a full synchronization is necessary.  If the last
// full synchronization was successful, it returns true if it's time for a new
// one.  Otherwise, it returns true if it's time for a retry.
func (db *Default) needsFullSync() (sinceFull time.Duration, isFull bool) {
	lastFull := db.lastFullSync
	sinceFull = time.Since(lastFull)
	if db.lastFullSyncError.IsZero() {
		return sinceFull, sinceFull >= db.fullSyncIvl
	}

	log.Info("profiledb: warning: %s since last successful full sync at %s", sinceFull, lastFull)

	sinceLastError := time.Since(db.lastFullSyncError)

	return sinceLastError, sinceLastError >= db.fullSyncRetryIvl
}

// loadFileCache loads the profiles data from the filesystem cache.
func (db *Default) loadFileCache() (err error) {
	const logPrefix = "profiledb: cache"

	start := time.Now()
	log.Info("%s: initial loading", logPrefix)

	c, err := db.cache.Load()
	if err != nil {
		if errors.Is(err, internal.CacheVersionError) {
			log.Info("%s: %s", logPrefix, err)

			return nil
		}

		// Don't wrap the error, because it's informative enough as is.
		return err
	} else if c == nil {
		log.Info("%s: no cache", logPrefix)

		return nil
	}

	profNum, devNum := len(c.Profiles), len(c.Devices)
	log.Info(
		"%s: got version %d, %d profiles, %d devices in %s",
		logPrefix,
		c.Version,
		profNum,
		devNum,
		time.Since(start),
	)

	if profNum == 0 || devNum == 0 {
		log.Info("%s: empty", logPrefix)

		return nil
	}

	db.setProfiles(c.Profiles, c.Devices, true)
	db.syncTime, db.lastFullSync = c.SyncTime, c.SyncTime

	return nil
}

// setProfiles adds or updates the data for all profiles and devices.
func (db *Default) setProfiles(profiles []*agd.Profile, devices []*agd.Device, isFullSync bool) {
	db.mapsMu.Lock()
	defer db.mapsMu.Unlock()

	if isFullSync {
		clear(db.profiles)
		clear(db.devices)
		clear(db.deviceIDToProfileID)
		clear(db.linkedIPToDeviceID)
		clear(db.dedicatedIPToDeviceID)
	}

	for _, p := range profiles {
		db.profiles[p.ID] = p

		for _, devID := range p.DeviceIDs {
			db.deviceIDToProfileID[devID] = p.ID
		}
	}

	for _, d := range devices {
		devID := d.ID
		db.devices[devID] = d

		if d.LinkedIP != (netip.Addr{}) {
			db.linkedIPToDeviceID[d.LinkedIP] = devID
		}

		for _, dedIP := range d.DedicatedIPs {
			db.dedicatedIPToDeviceID[dedIP] = devID
		}
	}
}

// type check
var _ Interface = (*Default)(nil)

// ProfileByDeviceID implements the [Interface] interface for *Default.
func (db *Default) ProfileByDeviceID(
	ctx context.Context,
	id agd.DeviceID,
) (p *agd.Profile, d *agd.Device, err error) {
	db.mapsMu.RLock()
	defer db.mapsMu.RUnlock()

	return db.profileByDeviceID(ctx, id)
}

// profileByDeviceID returns the profile and the device by the ID of the device,
// if found.  It assumes that db.mapsMu is locked for reading.
func (db *Default) profileByDeviceID(
	_ context.Context,
	id agd.DeviceID,
) (p *agd.Profile, d *agd.Device, err error) {
	// Do not use [errors.Annotate] here, because it allocates even when the
	// error is nil.  Also do not use fmt.Errorf in a defer, because it
	// allocates when a device is not found, which is the most common case.

	profID, ok := db.deviceIDToProfileID[id]
	if !ok {
		return nil, nil, ErrDeviceNotFound
	}

	p, ok = db.profiles[profID]
	if !ok {
		// We have an older device record with a deleted profile.  Remove it
		// from our profile DB in a goroutine, since that requires a write lock.
		go db.removeDevice(id)

		return nil, nil, fmt.Errorf("empty profile: %w", ErrDeviceNotFound)
	}

	// Reinspect the devices in the profile record to make sure that the device
	// is still attached to this profile.
	for _, profDevID := range p.DeviceIDs {
		if profDevID == id {
			d = db.devices[id]

			break
		}
	}

	if d == nil {
		// Perhaps, the device has been deleted from this profile.  May happen
		// when the device was found by a linked IP.  Remove it from our profile
		// DB in a goroutine, since that requires a write lock.
		go db.removeDevice(id)

		return nil, nil, fmt.Errorf("rechecking devices: %w", ErrDeviceNotFound)
	}

	return p, d, nil
}

// removeDevice removes the device with the given ID from the database.  It is
// intended to be used as a goroutine.
func (db *Default) removeDevice(id agd.DeviceID) {
	defer log.OnPanicAndExit("removeDevice", 1)

	db.mapsMu.Lock()
	defer db.mapsMu.Unlock()

	delete(db.deviceIDToProfileID, id)
}

// ProfileByLinkedIP implements the [Interface] interface for *Default.  ip must
// be valid.
func (db *Default) ProfileByLinkedIP(
	ctx context.Context,
	ip netip.Addr,
) (p *agd.Profile, d *agd.Device, err error) {
	// Do not use errors.Annotate here, because it allocates even when the error
	// is nil.  Also do not use fmt.Errorf in a defer, because it allocates when
	// a device is not found, which is the most common case.

	db.mapsMu.RLock()
	defer db.mapsMu.RUnlock()

	id, ok := db.linkedIPToDeviceID[ip]
	if !ok {
		return nil, nil, ErrDeviceNotFound
	}

	const errPrefix = "profile by device linked ip"
	p, d, err = db.profileByDeviceID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			// Probably, the device has been deleted.  Remove it from our
			// profile DB in a goroutine, since that requires a write lock.
			go db.removeLinkedIP(ip)
		}

		// Don't add the device ID to the error here, since it is already added
		// by profileByDeviceID.
		return nil, nil, fmt.Errorf("%s: %w", errPrefix, err)
	}

	if d.LinkedIP == (netip.Addr{}) {
		return nil, nil, fmt.Errorf(
			"%s: device does not have linked ip: %w",
			errPrefix,
			ErrDeviceNotFound,
		)
	} else if d.LinkedIP != ip {
		// The linked IP has changed.  Remove it from our profile DB in a
		// goroutine, since that requires a write lock.
		go db.removeLinkedIP(ip)

		return nil, nil, fmt.Errorf(
			"%s: %q doesn't match: %w",
			errPrefix,
			d.LinkedIP,
			ErrDeviceNotFound,
		)
	}

	return p, d, nil
}

// removeLinkedIP removes the device link for the given linked IP address from
// the profile database.  It is intended to be used as a goroutine.
func (db *Default) removeLinkedIP(ip netip.Addr) {
	defer log.OnPanicAndExit("removeLinkedIP", 1)

	db.mapsMu.Lock()
	defer db.mapsMu.Unlock()

	delete(db.linkedIPToDeviceID, ip)
}

// ProfileByDedicatedIP implements the [Interface] interface for *Default.  ip
// must be valid.
func (db *Default) ProfileByDedicatedIP(
	ctx context.Context,
	ip netip.Addr,
) (p *agd.Profile, d *agd.Device, err error) {
	// Do not use errors.Annotate here, because it allocates even when the error
	// is nil.  Also do not use fmt.Errorf in a defer, because it allocates when
	// a device is not found, which is the most common case.

	db.mapsMu.RLock()
	defer db.mapsMu.RUnlock()

	id, ok := db.dedicatedIPToDeviceID[ip]
	if !ok {
		return nil, nil, ErrDeviceNotFound
	}

	const errPrefix = "profile by device dedicated ip"
	p, d, err = db.profileByDeviceID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			// Probably, the device has been deleted.  Remove it from our
			// profile DB in a goroutine, since that requires a write lock.
			go db.removeDedicatedIP(ip)
		}

		// Don't add the device ID to the error here, since it is already added
		// by profileByDeviceID.
		return nil, nil, fmt.Errorf("%s: %w", errPrefix, err)
	}

	if ipIdx := slices.Index(d.DedicatedIPs, ip); ipIdx < 0 {
		// Perhaps, the device has changed its dedicated IPs.  Remove it from
		// our profile DB in a goroutine, since that requires a write lock.
		go db.removeDedicatedIP(ip)

		return nil, nil, fmt.Errorf(
			"%s: rechecking dedicated ips: %w",
			errPrefix,
			ErrDeviceNotFound,
		)
	}

	return p, d, nil
}

// removeDedicatedIP removes the device link for the given dedicated IP address
// from the profile database.  It is intended to be used as a goroutine.
func (db *Default) removeDedicatedIP(ip netip.Addr) {
	defer log.OnPanicAndExit("removeDedicatedIP", 1)

	db.mapsMu.Lock()
	defer db.mapsMu.Unlock()

	delete(db.dedicatedIPToDeviceID, ip)
}
