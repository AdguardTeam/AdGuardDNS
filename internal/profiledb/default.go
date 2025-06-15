package profiledb

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/filecachepb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/timeutil"
)

// Default is the default in-memory implementation of the [Interface] interface
// that can refresh itself from the provided storage.  It should be initially
// refreshed before use.
type Default struct {
	logger *slog.Logger

	// mapsMu protects:
	//   - dedicatedIPToDeviceID
	//   - deviceIDToProfileID
	//   - devices
	//   - humanIDToDeviceID
	//   - linkedIPToDeviceID
	//   - profiles
	//   - wellKnownPaths
	mapsMu *sync.RWMutex

	// refreshMu serializes Refresh calls and access to all values used inside
	// of it.
	refreshMu *sync.Mutex

	// cache is the filesystem-cache storage used by this profile database.
	cache internal.FileCacheStorage

	// clock is used to get current time during refreshes.
	clock timeutil.Clock

	// customDomainDB stores information about well-known paths for certificate
	// validation and custom-domain certificate data.
	customDomainDB CustomDomainDB

	// errColl is used to collect errors during refreshes.
	errColl errcoll.Interface

	// metrics is used for the collection of the user profiles statistics.
	metrics Metrics

	// storage returns the data for this profile DB.
	storage Storage

	// profiles maps profile IDs to profile records.
	profiles map[agd.ProfileID]*agd.Profile

	// devices maps device IDs to device records.
	devices map[agd.DeviceID]*agd.Device

	// dedicatedIPToDeviceID maps dedicated IP addresses to the IDs of their
	// devices.
	dedicatedIPToDeviceID map[netip.Addr]agd.DeviceID

	// deviceIDToProfileID maps device IDs to the ID of their profile.
	deviceIDToProfileID map[agd.DeviceID]agd.ProfileID

	// humanIDToDeviceID maps human-readable device-ID data to the IDs of the
	// devices.
	humanIDToDeviceID map[humanIDKey]agd.DeviceID

	// linkedIPToDeviceID maps linked IP addresses to the IDs of their devices.
	linkedIPToDeviceID map[netip.Addr]agd.DeviceID

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

// humanIDKey is the data necessary to identify a device by the lowercase
// version of its human-readable identifier and the ID of its profile.
type humanIDKey struct {
	// lower is the lowercase version of the human-readable device ID.
	lower agd.HumanIDLower

	// profile is the ID of the profile for the device.
	profile agd.ProfileID
}

// New returns a new default in-memory profile database with a filesystem cache.
// db is not nil if the error is from getting the file cache.  c must not be nil
// and must be valid.
func New(c *Config) (db *Default, err error) {
	var cacheStorage internal.FileCacheStorage
	if c.CacheFilePath == "none" {
		cacheStorage = internal.EmptyFileCacheStorage{}
	} else if ext := filepath.Ext(c.CacheFilePath); ext == ".pb" {
		cacheStorage = filecachepb.New(&filecachepb.Config{
			ProfileMetrics:       c.ProfileMetrics,
			Logger:               c.Logger.With("cache_type", "pb"),
			BaseCustomLogger:     c.BaseCustomLogger,
			CacheFilePath:        c.CacheFilePath,
			ResponseSizeEstimate: c.ResponseSizeEstimate,
		})
	} else {
		return nil, fmt.Errorf("file %q is not protobuf", c.CacheFilePath)
	}

	db = &Default{
		logger:                c.Logger,
		mapsMu:                &sync.RWMutex{},
		refreshMu:             &sync.Mutex{},
		cache:                 cacheStorage,
		clock:                 c.Clock,
		customDomainDB:        c.CustomDomainDB,
		errColl:               c.ErrColl,
		metrics:               c.Metrics,
		storage:               c.Storage,
		syncTime:              time.Time{},
		lastFullSync:          time.Time{},
		lastFullSyncError:     time.Time{},
		profiles:              make(map[agd.ProfileID]*agd.Profile),
		devices:               make(map[agd.DeviceID]*agd.Device),
		deviceIDToProfileID:   make(map[agd.DeviceID]agd.ProfileID),
		dedicatedIPToDeviceID: make(map[netip.Addr]agd.DeviceID),
		humanIDToDeviceID:     make(map[humanIDKey]agd.DeviceID),
		linkedIPToDeviceID:    make(map[netip.Addr]agd.DeviceID),
		fullSyncIvl:           c.FullSyncIvl,
		fullSyncRetryIvl:      c.FullSyncRetryIvl,
	}

	// TODO(a.garipov):  Separate the file cache read and use context from the
	// arguments.
	ctx := context.Background()
	err = db.loadFileCache(ctx)
	if err != nil {
		db.logger.WarnContext(ctx, "error loading fs cache", slogutil.KeyError, err)
	}

	return db, nil
}

// type check
var _ service.Refresher = (*Default)(nil)

// Refresh implements the [service.Refresher] interface for *Default.  It
// updates the internal maps and the synchronization time using the data it
// receives from the storage.
func (db *Default) Refresh(ctx context.Context) (err error) {
	db.refreshMu.Lock()
	defer db.refreshMu.Unlock()

	if db.needsFullSync(ctx) {
		return db.refreshFull(ctx)
	}

	db.logger.DebugContext(ctx, "refresh started")
	defer db.logger.DebugContext(ctx, "refresh finished")

	reqID := agd.NewRequestID()
	ctx = agd.WithRequestID(ctx, reqID)

	var profNum, devNum uint
	startTime := db.clock.Now()
	defer func() {
		err = errors.Annotate(err, "req %s: %w", reqID)
		if err != nil {
			errcoll.Collect(ctx, db.errColl, db.logger, "refreshing profiledb", err)
		}

		db.metrics.SetProfilesAndDevicesNum(ctx, uint(len(db.profiles)), uint(len(db.devices)))
		db.metrics.HandleProfilesUpdate(ctx, &UpdateMetrics{
			ProfilesNum: profNum,
			DevicesNum:  devNum,
			Duration:    time.Since(startTime),
			IsSuccess:   err == nil,
			IsFullSync:  false,
		})
	}()

	resp, err := db.fetchProfiles(ctx, false)
	if err != nil {
		return fmt.Errorf("fetching profiles: %w", err)
	}

	profiles := resp.Profiles
	devices := resp.Devices

	profNum = uint(len(profiles))
	devNum = uint(len(devices))

	db.setProfiles(ctx, profiles, devices, resp.DeviceChanges)

	return nil
}

// setProfiles adds or updates the data for all profiles and devices from a
// non-full sync.
func (db *Default) setProfiles(
	ctx context.Context,
	profiles []*agd.Profile,
	devices []*agd.Device,
	devChanges map[agd.ProfileID]*StorageDeviceChange,
) {
	db.mapsMu.Lock()
	defer db.mapsMu.Unlock()

	for _, p := range profiles {
		db.applyChanges(p, devChanges[p.ID])

		db.profiles[p.ID] = p

		err := db.setProfileCerts(ctx, p)
		if err != nil {
			err = fmt.Errorf("profile %q: %w", p.ID, err)
			errcoll.Collect(ctx, db.errColl, db.logger, "setting profile certs", err)
		}

		for devID := range p.DeviceIDs.Range {
			db.deviceIDToProfileID[devID] = p.ID
		}

		if p.Deleted {
			// The deleted profiles are included in profiles slice only if it is
			// not a full sync.  If setProfiles is called when loading from
			// cache, the profiles slice does not include the deleted profiles,
			// so we can update metric correctly.
			db.metrics.IncrementDeleted(ctx)
		}
	}

	db.setDevices(ctx, devices)
}

// applyChanges adds the data from the previous profile, if any, and device
// changes, if there is one and it's partial, to p.  db.mapsMu must be locked
// for writing.  p must not be nil.
func (db *Default) applyChanges(p *agd.Profile, devChg *StorageDeviceChange) {
	if devChg == nil || !devChg.IsPartial {
		return
	}

	// Since this is a partial update, and there may be deleted devices, process
	// them by merging the previous device IDs and deleting those that should be
	// deleted.
	prev, ok := db.profiles[p.ID]
	if !ok {
		return
	}

	// TODO(a.garipov):  Consider adding container.MapSet.Union.
	for prevID := range prev.DeviceIDs.Range {
		p.DeviceIDs.Add(prevID)
	}

	for _, delDevID := range devChg.DeletedDeviceIDs {
		p.DeviceIDs.Delete(delDevID)
		delete(db.deviceIDToProfileID, delDevID)
		// Do not delete it from [db.devices], since the device could have been
		// moved to another profile.
	}
}

// setProfileCerts sets the certificate information for the profile.  p must not
// be nil and must be valid.  db.mapsMu must be locked for writing.
//
// TODO(a.garipov):  Extend with current certs.
func (db *Default) setProfileCerts(ctx context.Context, p *agd.Profile) (err error) {
	cd := p.CustomDomains
	if !cd.Enabled {
		// Assume that the expired pending paths are cleaned up either by
		// [db.IsValidWellKnownRequest] or in a full sync.
		return
	}

	var errs []error
	for i, c := range cd.Domains {
		switch s := c.State.(type) {
		case *agd.CustomDomainStateCurrent:
			db.customDomainDB.AddCertificate(ctx, c.Domains, s)
		case *agd.CustomDomainStatePending:
			db.customDomainDB.SetWellKnownPath(ctx, s)
		default:
			errs = append(errs, fmt.Errorf("custom domains: at index %d: bad type %T(%[2]v)", i, s))
		}
	}

	return errors.Join(errs...)
}

// setDevices adds or updates the data for the given devices.  db.mapsMu must be
// locked for writing.
func (db *Default) setDevices(ctx context.Context, devices []*agd.Device) {
	for _, d := range devices {
		devID := d.ID
		db.devices[devID] = d

		for _, dedIP := range d.DedicatedIPs {
			db.dedicatedIPToDeviceID[dedIP] = devID
		}

		if d.LinkedIP != (netip.Addr{}) {
			db.linkedIPToDeviceID[d.LinkedIP] = devID
		}

		if d.HumanIDLower == "" {
			continue
		}

		profID, ok := db.deviceIDToProfileID[devID]
		if !ok {
			db.logger.WarnContext(ctx, "no profile id for device", "dev_id", devID)

			continue
		}

		db.humanIDToDeviceID[humanIDKey{
			lower:   d.HumanIDLower,
			profile: profID,
		}] = devID
	}
}

// RefreshFull is a [service.RefresherFunc] that updates the internal maps and
// the synchronization time using the data it receives from the storage.
func (db *Default) RefreshFull(ctx context.Context) (err error) {
	db.refreshMu.Lock()
	defer db.refreshMu.Unlock()

	return db.refreshFull(ctx)
}

// refreshFull updates the internal maps and the synchronization time using the
// data it receives from the storage.  db.refreshMu must be locked.
func (db *Default) refreshFull(ctx context.Context) (err error) {
	db.logger.DebugContext(ctx, "full refresh started")
	defer db.logger.DebugContext(ctx, "full refresh finished")

	reqID := agd.NewRequestID()
	ctx = agd.WithRequestID(ctx, reqID)

	var profNum, devNum uint
	startTime := db.clock.Now()
	defer func() {
		err = errors.Annotate(err, "req %s: %w", reqID)
		if err != nil {
			errcoll.Collect(ctx, db.errColl, db.logger, "full refreshing profiledb", err)
		}

		db.metrics.SetProfilesAndDevicesNum(ctx, uint(len(db.profiles)), uint(len(db.devices)))
		db.metrics.HandleProfilesUpdate(ctx, &UpdateMetrics{
			ProfilesNum: profNum,
			DevicesNum:  devNum,
			Duration:    time.Since(startTime),
			IsSuccess:   err == nil,
			IsFullSync:  true,
		})
	}()

	resp, err := db.fetchProfiles(ctx, true)
	if err != nil {
		db.lastFullSyncError = db.clock.Now()

		return fmt.Errorf("fetching profiles: full sync: %w", err)
	}

	profiles := resp.Profiles
	devices := resp.Devices

	profNum = uint(len(profiles))
	devNum = uint(len(devices))

	db.setProfilesFull(ctx, profiles, devices)

	db.lastFullSync = db.clock.Now()
	db.lastFullSyncError = time.Time{}

	err = db.cache.Store(ctx, &internal.FileCache{
		SyncTime: db.syncTime,
		Profiles: profiles,
		Devices:  devices,
		Version:  internal.FileCacheVersion,
	})
	if err != nil {
		return fmt.Errorf("saving cache: %w", err)
	}

	return nil
}

// requestSyncTime returns the time to use in the storage request.  db.refreshMu
// must be locked.
func (db *Default) requestSyncTime(ctx context.Context, isFullSync bool) (syncTime time.Time) {
	if !isFullSync {
		return db.syncTime
	}

	sinceLastAttempt := db.sinceLastFull()
	db.logger.InfoContext(ctx, "full sync", "since_last_attempt", sinceLastAttempt)

	return syncTimeFull
}

// fetchProfiles fetches the profiles and devices from the storage.  It returns
// the response and the error, if any.  db.refreshMu must be locked.
func (db *Default) fetchProfiles(
	ctx context.Context,
	isFullSync bool,
) (sr *StorageProfilesResponse, err error) {
	sr, err = db.storage.Profiles(ctx, &StorageProfilesRequest{
		SyncTime: db.requestSyncTime(ctx, isFullSync),
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			db.metrics.IncrementSyncTimeouts(ctx, isFullSync)
		}

		return nil, fmt.Errorf("updating profiles: %w", err)
	}

	db.syncTime = sr.SyncTime

	db.logger.DebugContext(
		ctx,
		"storage request finished",
		"is_full", isFullSync,
		"prof_num", uint(len(sr.Profiles)),
		"dev_num", uint(len(sr.Devices)),
		"chg_num", uint(len(sr.DeviceChanges)),
	)

	return sr, nil
}

// needsFullSync determines if a full synchronization is necessary.  If the last
// full synchronization was successful, it returns true if it's time for a new
// one.  Otherwise, it returns true if it's time for a retry.  db.refreshMu must
// be locked.
func (db *Default) needsFullSync(ctx context.Context) (isFull bool) {
	lastFull := db.lastFullSync
	sinceFull := time.Since(lastFull)

	if db.lastFullSyncError.IsZero() {
		return sinceFull >= db.fullSyncIvl
	}

	db.logger.WarnContext(
		ctx,
		"previous sync finished with error",
		"since_last_successful_sync", sinceFull,
		"last_successful_sync_time", lastFull,
	)

	sinceLastError := time.Since(db.lastFullSyncError)

	return sinceLastError >= db.fullSyncRetryIvl
}

// sinceLastFull returns a time duration since the last full synchronization
// attempt.  db.refreshMu must be locked.
func (db *Default) sinceLastFull() (sinceFull time.Duration) {
	if !db.lastFullSyncError.IsZero() {
		return time.Since(db.lastFullSyncError)
	}

	return time.Since(db.lastFullSync)
}

// loadFileCache loads the profiles data from the filesystem cache.
func (db *Default) loadFileCache(ctx context.Context) (err error) {
	start := db.clock.Now()

	l := db.logger.With("cache_op", "load")
	l.InfoContext(ctx, "initial loading")

	c, err := db.cache.Load(ctx)
	if err != nil {
		if errors.Is(err, internal.CacheVersionError) {
			l.WarnContext(ctx, "cache version error", slogutil.KeyError, err)

			return nil
		}

		// Don't wrap the error, because it's informative enough as is.
		return err
	} else if c == nil {
		l.InfoContext(ctx, "no cache")

		return nil
	}

	profNum, devNum := len(c.Profiles), len(c.Devices)
	l.InfoContext(
		ctx,
		"cache loaded",
		"version", c.Version,
		"prof_num", profNum,
		"dev_num", devNum,
		"elapsed", time.Since(start),
	)

	if profNum == 0 || devNum == 0 {
		l.InfoContext(ctx, "cache is empty; not setting profiles")

		return nil
	}

	db.setProfilesFull(ctx, c.Profiles, c.Devices)
	db.syncTime, db.lastFullSync = c.SyncTime, c.SyncTime

	return nil
}

// setProfilesFull adds the data for all profiles and devices after a full sync.
func (db *Default) setProfilesFull(
	ctx context.Context,
	profiles []*agd.Profile,
	devices []*agd.Device,
) {
	db.mapsMu.Lock()
	defer db.mapsMu.Unlock()

	clear(db.profiles)
	clear(db.devices)
	clear(db.dedicatedIPToDeviceID)
	clear(db.deviceIDToProfileID)
	clear(db.humanIDToDeviceID)
	clear(db.linkedIPToDeviceID)

	db.customDomainDB.DeleteAllWellKnownPaths(ctx)

	for i, p := range profiles {
		db.profiles[p.ID] = p

		for devID := range p.DeviceIDs.Range {
			db.deviceIDToProfileID[devID] = p.ID
		}

		err := db.setProfileCerts(ctx, p)
		if err != nil {
			err = fmt.Errorf("profiles: at index %d: %w", i, err)
			errcoll.Collect(ctx, db.errColl, db.logger, "setting profile certs in full sync", err)
		}
	}

	db.setDevices(ctx, devices)
}

// type check
var _ Interface = (*Default)(nil)

// CreateAutoDevice implements the [Interface] interface for *Default.
func (db *Default) CreateAutoDevice(
	ctx context.Context,
	id agd.ProfileID,
	humanID agd.HumanID,
	devType agd.DeviceType,
) (p *agd.Profile, d *agd.Device, err error) {
	var ok bool
	func() {
		db.mapsMu.RLock()
		defer db.mapsMu.RUnlock()

		p, ok = db.profiles[id]
	}()
	if !ok {
		return nil, nil, ErrProfileNotFound
	}

	if !p.AutoDevicesEnabled {
		// If the user did not enable the automatic devices feature, treat it
		// the same as if this profile did not exist.
		return nil, nil, ErrProfileNotFound
	}

	resp, err := db.storage.CreateAutoDevice(ctx, &StorageCreateAutoDeviceRequest{
		ProfileID:  id,
		HumanID:    humanID,
		DeviceType: devType,
	})
	if err != nil {
		return nil, nil, err
	}

	d = resp.Device

	func() {
		db.mapsMu.Lock()
		defer db.mapsMu.Unlock()

		// TODO(a.garipov):  Technically, we must also update p.DeviceIDs, but
		// this is hard to do without races, since all methods of the profile
		// database return values as opposed to clones.  This can cause issues
		// when the same device is used both by a HumanID and a DeviceID, but we
		// consider this situation to be relatively rare.

		db.setDevices(ctx, []*agd.Device{d})
	}()

	return p, d, nil
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
			go db.removeDedicatedIP(ctx, ip)
		}

		// Don't add the device ID to the error here, since it is already added
		// by profileByDeviceID.
		return nil, nil, fmt.Errorf("%s: %w", errPrefix, err)
	}

	if !slices.Contains(d.DedicatedIPs, ip) {
		// Perhaps, the device has changed its dedicated IPs.  Remove it from
		// our profile DB in a goroutine, since that requires a write lock.
		go db.removeDedicatedIP(ctx, ip)

		return nil, nil, fmt.Errorf(
			"%s: rechecking dedicated ips: %w",
			errPrefix,
			ErrDeviceNotFound,
		)
	}

	return p, d, nil
}

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
// if found.  db.mapsMu must be locked for reading.
func (db *Default) profileByDeviceID(
	ctx context.Context,
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
		go db.removeDevice(ctx, id)

		return nil, nil, ErrProfileNotFound
	}

	// Reinspect the devices in the profile record to make sure that the device
	// is still attached to this profile.
	if p.DeviceIDs.Has(id) {
		d = db.devices[id]
	}

	if d == nil {
		if !p.AutoDevicesEnabled {
			// Perhaps, the device has been deleted from this profile.  May
			// happen when the device was found by a linked IP.  Remove it from
			// our profile DB in a goroutine, since that requires a write lock.
			//
			// Do not do that for profiles with enabled autodevices, though.
			// See the TODO in [Default.CreateAutoDevice].
			go db.removeDevice(ctx, id)
		}

		return nil, nil, fmt.Errorf("rechecking devices: %w", ErrDeviceNotFound)
	}

	return p, d, nil
}

// removeDevice removes the device with the given ID from the database.  It is
// intended to be used as a goroutine.
func (db *Default) removeDevice(ctx context.Context, id agd.DeviceID) {
	defer slogutil.RecoverAndExit(ctx, db.logger, osutil.ExitCodeFailure)

	db.mapsMu.Lock()
	defer db.mapsMu.Unlock()

	delete(db.deviceIDToProfileID, id)
}

// removeDedicatedIP removes the device link for the given dedicated IP address
// from the profile database.  It is intended to be used as a goroutine.
func (db *Default) removeDedicatedIP(ctx context.Context, ip netip.Addr) {
	defer slogutil.RecoverAndExit(ctx, db.logger, osutil.ExitCodeFailure)

	db.mapsMu.Lock()
	defer db.mapsMu.Unlock()

	delete(db.dedicatedIPToDeviceID, ip)
}

// ProfileByHumanID implements the [Interface] interface for *Default.
func (db *Default) ProfileByHumanID(
	ctx context.Context,
	id agd.ProfileID,
	humanID agd.HumanIDLower,
) (p *agd.Profile, d *agd.Device, err error) {
	// Do not use errors.Annotate here, because it allocates even when the error
	// is nil.  Also do not use fmt.Errorf in a defer, because it allocates when
	// a device is not found, which is the most common case.

	db.mapsMu.RLock()
	defer db.mapsMu.RUnlock()

	// NOTE:  It's important to check the profile and return ErrProfileNotFound
	// here to prevent the device finder from trying to create a device for a
	// profile that doesn't exist.
	p, ok := db.profiles[id]
	if !ok {
		return nil, nil, ErrProfileNotFound
	}

	k := humanIDKey{
		lower:   humanID,
		profile: id,
	}
	devID, ok := db.humanIDToDeviceID[k]
	if !ok {
		return nil, nil, ErrDeviceNotFound
	}

	const errPrefix = "profile by human id"
	p, d, err = db.profileByDeviceID(ctx, devID)
	if err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			// Probably, the device has been deleted.  Remove it from our
			// profile DB in a goroutine, since that requires a write lock.
			go db.removeHumanID(ctx, k)
		}

		// Don't add the device ID to the error here, since it is already added
		// by profileByDeviceID.
		return nil, nil, fmt.Errorf("%s: %w", errPrefix, err)
	}

	if humanID != d.HumanIDLower {
		// Perhaps, the device has changed its human ID, for example by being
		// transformed into a normal device..  Remove it from our profile DB in
		// a goroutine, since that requires a write lock.
		go db.removeHumanID(ctx, k)

		return nil, nil, fmt.Errorf("%s: rechecking human id: %w", errPrefix, ErrDeviceNotFound)
	}

	return p, d, nil
}

// removeHumanID removes the device link for the given key from the profile
// database.  It is intended to be used as a goroutine.
func (db *Default) removeHumanID(ctx context.Context, k humanIDKey) {
	defer slogutil.RecoverAndExit(ctx, db.logger, osutil.ExitCodeFailure)

	db.mapsMu.Lock()
	defer db.mapsMu.Unlock()

	delete(db.humanIDToDeviceID, k)
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
			go db.removeLinkedIP(ctx, ip)
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
		go db.removeLinkedIP(ctx, ip)

		return nil, nil, fmt.Errorf(
			"%s: %q does not match: %w",
			errPrefix,
			d.LinkedIP,
			ErrDeviceNotFound,
		)
	}

	return p, d, nil
}

// removeLinkedIP removes the device link for the given linked IP address from
// the profile database.  It is intended to be used as a goroutine.
func (db *Default) removeLinkedIP(ctx context.Context, ip netip.Addr) {
	defer slogutil.RecoverAndExit(ctx, db.logger, osutil.ExitCodeFailure)

	db.mapsMu.Lock()
	defer db.mapsMu.Unlock()

	delete(db.linkedIPToDeviceID, ip)
}
