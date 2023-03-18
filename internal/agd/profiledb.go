package agd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
)

// Data Storage

// ProfileDB is the local database of profiles and other data.
//
// TODO(a.garipov): move this logic to the backend package.
type ProfileDB interface {
	ProfileByDeviceID(ctx context.Context, id DeviceID) (p *Profile, d *Device, err error)
	ProfileByIP(ctx context.Context, ip netip.Addr) (p *Profile, d *Device, err error)
}

// DefaultProfileDB is the default implementation of the ProfileDB interface
// that can refresh itself from the provided storage.
type DefaultProfileDB struct {
	// mapsMu protects the deviceToProfile, deviceIDToIP, and ipToDeviceID maps.
	mapsMu *sync.RWMutex

	// refreshMu protects syncTime and syncTimeFull.  These are only used within
	// Refresh, so this is also basically a refresh serializer.
	refreshMu *sync.Mutex

	// storage returns the data for this profiledb.
	storage ProfileStorage

	// deviceToProfile maps device IDs to their profiles.  It is cleared lazily
	// whenever a device is found to be missing from a profile.
	deviceToProfile map[DeviceID]*Profile

	// deviceIDToIP maps device IDs to their linked IP addresses.  It is used to
	// take changes in IP address linking into account during refreshes.  It is
	// cleared lazily whenever a device is found to be missing from a profile.
	deviceIDToIP map[DeviceID]netip.Addr

	// ipToDeviceID maps linked IP addresses to the IDs of their devices.  It is
	// cleared lazily whenever a device is found to be missing from a profile.
	ipToDeviceID map[netip.Addr]DeviceID

	// syncTime is the time of the last synchronization.  It is used in refresh
	// requests to the storage.
	syncTime time.Time

	// syncTimeFull is the time of the last full synchronization.
	syncTimeFull time.Time

	// cacheFilePath is the path to profiles cache file.
	cacheFilePath string

	// fullSyncIvl is the interval between two full synchronizations with the
	// storage
	fullSyncIvl time.Duration
}

// NewDefaultProfileDB returns a new default profile profiledb.  The initial
// refresh is performed immediately with the constant timeout of 1 minute,
// beyond which an empty profiledb is returned.  db is never nil.
func NewDefaultProfileDB(
	ds ProfileStorage,
	fullRefreshIvl time.Duration,
	cacheFilePath string,
) (db *DefaultProfileDB, err error) {
	db = &DefaultProfileDB{
		mapsMu:          &sync.RWMutex{},
		refreshMu:       &sync.Mutex{},
		storage:         ds,
		syncTime:        time.Time{},
		syncTimeFull:    time.Time{},
		deviceToProfile: make(map[DeviceID]*Profile),
		deviceIDToIP:    make(map[DeviceID]netip.Addr),
		ipToDeviceID:    make(map[netip.Addr]DeviceID),
		fullSyncIvl:     fullRefreshIvl,
		cacheFilePath:   cacheFilePath,
	}

	err = db.loadProfileCache()
	if err != nil {
		log.Error("profiledb: cache: loading: %s", err)
	}

	// initialTimeout defines the maximum duration of the first attempt to load
	// the profiledb.
	const initialTimeout = 1 * time.Minute

	ctx, cancel := context.WithTimeout(context.Background(), initialTimeout)
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
var _ Refresher = (*DefaultProfileDB)(nil)

// Refresh implements the Refresher interface for *DefaultProfileDB.  It updates
// the internal maps from the data it receives from the storage.
func (db *DefaultProfileDB) Refresh(ctx context.Context) (err error) {
	startTime := time.Now()
	defer func() {
		metrics.ProfilesSyncTime.SetToCurrentTime()
		metrics.ProfilesCountGauge.Set(float64(len(db.deviceToProfile)))
		metrics.ProfilesSyncDuration.Observe(time.Since(startTime).Seconds())
		metrics.SetStatusGauge(metrics.ProfilesSyncStatus, err)
	}()

	reqID := NewRequestID()
	ctx = WithRequestID(ctx, reqID)

	defer func() { err = errors.Annotate(err, "req %s: %w", reqID) }()

	db.refreshMu.Lock()
	defer db.refreshMu.Unlock()

	isFullSync := time.Since(db.syncTimeFull) >= db.fullSyncIvl
	syncTime := db.syncTime
	if isFullSync {
		syncTime = time.Time{}
	}

	var resp *PSProfilesResponse
	resp, err = db.storage.Profiles(ctx, &PSProfilesRequest{
		SyncTime: syncTime,
	})
	if err != nil {
		return fmt.Errorf("updating profiles: %w", err)
	}

	profiles := resp.Profiles
	devNum := db.setProfiles(profiles)
	log.Debug("profiledb: req %s: got %d profiles with %d devices", reqID, len(profiles), devNum)
	metrics.ProfilesNewCountGauge.Set(float64(len(profiles)))

	db.syncTime = resp.SyncTime
	if isFullSync {
		db.syncTimeFull = time.Now()

		err = db.saveProfileCache(ctx)
		if err != nil {
			return fmt.Errorf("saving cache: %w", err)
		}
	}

	return nil
}

// profileCache is the structure for profiles db cache.
type profileCache struct {
	SyncTime time.Time  `json:"sync_time"`
	Profiles []*Profile `json:"profiles"`
	Version  int        `json:"version"`
}

// saveStorageCache saves profiles data to cache file.
func (db *DefaultProfileDB) saveProfileCache(ctx context.Context) (err error) {
	log.Info("profiledb: saving profile cache")

	var resp *PSProfilesResponse
	resp, err = db.storage.Profiles(ctx, &PSProfilesRequest{
		SyncTime: time.Time{},
	})

	if err != nil {
		return err
	}

	data := &profileCache{
		Profiles: resp.Profiles,
		Version:  defaultProfileDBCacheVersion,
		SyncTime: time.Now(),
	}

	cache, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encoding json: %w", err)
	}

	err = os.WriteFile(db.cacheFilePath, cache, 0o600)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	log.Info("profiledb: cache: saved %d profiles to %q", len(resp.Profiles), db.cacheFilePath)

	return nil
}

// defaultProfileDBCacheVersion is the version of cached data structure.  It's
// manually incremented on every change in [profileCache] structure.
const defaultProfileDBCacheVersion = 2

// loadProfileCache loads profiles data from cache file.
func (db *DefaultProfileDB) loadProfileCache() (err error) {
	log.Info("profiledb: loading cache")

	data, err := db.loadStorageCache()
	if err != nil {
		return fmt.Errorf("loading cache: %w", err)
	}

	if data == nil {
		log.Info("profiledb: cache is empty")

		return nil
	}

	if data.Version == defaultProfileDBCacheVersion {
		profiles := data.Profiles
		devNum := db.setProfiles(profiles)
		log.Info("profiledb: cache: got %d profiles with %d devices", len(profiles), devNum)

		db.syncTime = data.SyncTime
		db.syncTimeFull = data.SyncTime
	} else {
		log.Info(
			"profiledb: cache version %d is different from %d",
			data.Version,
			defaultProfileDBCacheVersion,
		)
	}

	return nil
}

// loadStorageCache loads data from cache file.
func (db *DefaultProfileDB) loadStorageCache() (data *profileCache, err error) {
	file, err := os.Open(db.cacheFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// File could be deleted or not yet created, go on.
			return nil, nil
		}

		return nil, err
	}
	defer func() { err = errors.WithDeferred(err, file.Close()) }()

	data = &profileCache{}
	err = json.NewDecoder(file).Decode(data)
	if err != nil {
		return nil, fmt.Errorf("decoding json: %w", err)
	}

	return data, nil
}

// setProfiles adds or updates the data for all profiles.
func (db *DefaultProfileDB) setProfiles(profiles []*Profile) (devNum int) {
	db.mapsMu.Lock()
	defer db.mapsMu.Unlock()

	for _, p := range profiles {
		devNum += len(p.Devices)
		for _, d := range p.Devices {
			db.deviceToProfile[d.ID] = p
			if d.LinkedIP == nil {
				// Delete any records from the device-to-IP map just in case
				// there used to be one.
				delete(db.deviceIDToIP, d.ID)

				continue
			}

			newIP := *d.LinkedIP
			if prevIP, ok := db.deviceIDToIP[d.ID]; !ok || prevIP != newIP {
				// The IP has changed.  Remove the previous records before
				// setting the new ones.
				delete(db.ipToDeviceID, prevIP)
				delete(db.deviceIDToIP, d.ID)
			}

			db.ipToDeviceID[newIP] = d.ID
			db.deviceIDToIP[d.ID] = newIP
		}
	}

	return devNum
}

// type check
var _ ProfileDB = (*DefaultProfileDB)(nil)

// ProfileByDeviceID implements the ProfileDB interface for *DefaultProfileDB.
func (db *DefaultProfileDB) ProfileByDeviceID(
	ctx context.Context,
	id DeviceID,
) (p *Profile, d *Device, err error) {
	db.mapsMu.RLock()
	defer db.mapsMu.RUnlock()

	return db.profileByDeviceID(ctx, id)
}

// profileByDeviceID returns the profile and the device by the ID of the device,
// if found.  Any returned errors will have the underlying type of
// NotFoundError.  It assumes that db is currently locked for reading.
func (db *DefaultProfileDB) profileByDeviceID(
	_ context.Context,
	id DeviceID,
) (p *Profile, d *Device, err error) {
	// Do not use errors.Annotate here, because it allocates even when the error
	// is nil.  Also do not use fmt.Errorf in a defer, because it allocates when
	// a device is not found, which is the most common case.
	//
	// TODO(a.garipov): Find out, why does it allocate and perhaps file an
	// issue about that in the Go issue tracker.

	var ok bool
	p, ok = db.deviceToProfile[id]
	if !ok {
		return nil, nil, ProfileNotFoundError{}
	}

	for _, pd := range p.Devices {
		if pd.ID == id {
			d = pd

			break
		}
	}

	if d == nil {
		// Perhaps, the device has been deleted.  May happen when the device was
		// found by a linked IP.
		return nil, nil, fmt.Errorf("rechecking devices: %w", DeviceNotFoundError{})
	}

	return p, d, nil
}

// ProfileByIP implements the ProfileDB interface for *DefaultProfileDB.  ip
// must be valid.
func (db *DefaultProfileDB) ProfileByIP(
	ctx context.Context,
	ip netip.Addr,
) (p *Profile, d *Device, err error) {
	// Do not use errors.Annotate here, because it allocates even when the error
	// is nil.  Also do not use fmt.Errorf in a defer, because it allocates when
	// a device is not found, which is the most common case.

	db.mapsMu.RLock()
	defer db.mapsMu.RUnlock()

	id, ok := db.ipToDeviceID[ip]
	if !ok {
		return nil, nil, DeviceNotFoundError{}
	}

	p, d, err = db.profileByDeviceID(ctx, id)
	if errors.Is(err, DeviceNotFoundError{}) {
		// Probably, the device has been deleted.  Remove it from our profiledb
		// in a goroutine, since that requires a write lock.
		go db.removeDeviceByIP(id, ip)

		// Go on and return the error.
	}

	if err != nil {
		// Don't add the device ID to the error here, since it is already added
		// by profileByDeviceID.
		return nil, nil, fmt.Errorf("profile by linked device id: %w", err)
	}

	return p, d, nil
}

// removeDeviceByIP removes the device with the given ID and linked IP address
// from the profiledb.  It is intended to be used as a goroutine.
func (db *DefaultProfileDB) removeDeviceByIP(id DeviceID, ip netip.Addr) {
	defer log.OnPanicAndExit("removeDeviceByIP", 1)

	db.mapsMu.Lock()
	defer db.mapsMu.Unlock()

	delete(db.ipToDeviceID, ip)
	delete(db.deviceIDToIP, id)
	delete(db.deviceToProfile, id)
}

// ProfileStorage is a storage of data about profiles and other entities.
type ProfileStorage interface {
	// Profiles returns all profiles known to this particular data storage.  req
	// must not be nil.
	Profiles(ctx context.Context, req *PSProfilesRequest) (resp *PSProfilesResponse, err error)
}

// PSProfilesRequest is the ProfileStorage.Profiles request.
type PSProfilesRequest struct {
	SyncTime time.Time
}

// PSProfilesResponse is the ProfileStorage.Profiles response.
type PSProfilesResponse struct {
	SyncTime time.Time
	Profiles []*Profile
}
