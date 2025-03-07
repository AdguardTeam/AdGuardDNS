// Package profiledb defines interfaces for databases of user profiles.
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
	"github.com/c2h5oh/datasize"
)

// Interface is the local database of user profiles and devices.
//
// NOTE:  All returned values must not be modified.
type Interface interface {
	// CreateAutoDevice creates a new automatic device for the given profile
	// with the given human-readable device ID and device type.  All arguments
	// must be valid.
	CreateAutoDevice(
		ctx context.Context,
		id agd.ProfileID,
		humanID agd.HumanID,
		devType agd.DeviceType,
	) (p *agd.Profile, d *agd.Device, err error)

	// ProfileByDedicatedIP returns the profile and the device identified by its
	// dedicated DNS server IP address.  ip must be valid.
	ProfileByDedicatedIP(
		ctx context.Context,
		ip netip.Addr,
	) (p *agd.Profile, d *agd.Device, err error)

	// ProfileByDeviceID returns the profile and the device identified by id.
	// id must be valid.
	ProfileByDeviceID(
		ctx context.Context,
		id agd.DeviceID,
	) (p *agd.Profile, d *agd.Device, err error)

	// ProfileByHumanID returns the profile and the device identified by the
	// profile ID and the lowercase version of the human-readable device ID.
	// id and humanIDLower must be valid.
	ProfileByHumanID(
		ctx context.Context,
		id agd.ProfileID,
		humanIDLower agd.HumanIDLower,
	) (p *agd.Profile, d *agd.Device, err error)

	// ProfileByLinkedIP returns the profile and the device identified by its
	// linked IP address.  ip must be valid.
	ProfileByLinkedIP(ctx context.Context, ip netip.Addr) (p *agd.Profile, d *agd.Device, err error)
}

// type check
var _ Interface = (*Disabled)(nil)

// Disabled is a profile database that panics on any call.
type Disabled struct{}

// profilesDBUnexpectedCall is a panic message template for lookup methods when
// profiles database is disabled.
const profilesDBUnexpectedCall string = "profiles db: unexpected call to %s"

// CreateAutoDevice implements the [Interface] interface for *Disabled.
func (d *Disabled) CreateAutoDevice(
	_ context.Context,
	_ agd.ProfileID,
	_ agd.HumanID,
	_ agd.DeviceType,
) (_ *agd.Profile, _ *agd.Device, _ error) {
	panic(fmt.Errorf(profilesDBUnexpectedCall, "CreateAutoDevice"))
}

// ProfileByDedicatedIP implements the [Interface] interface for *Disabled.
func (d *Disabled) ProfileByDedicatedIP(
	_ context.Context,
	_ netip.Addr,
) (_ *agd.Profile, _ *agd.Device, _ error) {
	panic(fmt.Errorf(profilesDBUnexpectedCall, "ProfileByDedicatedIP"))
}

// ProfileByDeviceID implements the [Interface] interface for *Disabled.
func (d *Disabled) ProfileByDeviceID(
	_ context.Context,
	_ agd.DeviceID,
) (_ *agd.Profile, _ *agd.Device, _ error) {
	panic(fmt.Errorf(profilesDBUnexpectedCall, "ProfileByDeviceID"))
}

// ProfileByHumanID implements the [Interface] interface for *Disabled.
func (d *Disabled) ProfileByHumanID(
	_ context.Context,
	_ agd.ProfileID,
	_ agd.HumanIDLower,
) (_ *agd.Profile, _ *agd.Device, _ error) {
	panic(fmt.Errorf(profilesDBUnexpectedCall, "ProfileByHumanID"))
}

// ProfileByLinkedIP implements the [Interface] interface for *Disabled.
func (d *Disabled) ProfileByLinkedIP(
	_ context.Context,
	_ netip.Addr,
) (_ *agd.Profile, _ *agd.Device, _ error) {
	panic(fmt.Errorf(profilesDBUnexpectedCall, "ProfileByLinkedIP"))
}

// Config represents the profile database configuration.  All fields must not be
// empty.
type Config struct {
	// Logger is used for logging the operation of profile database.
	Logger *slog.Logger

	// BaseCustomLogger is the base logger used for the custom filters.
	BaseCustomLogger *slog.Logger

	// Storage returns the data for this profile DB.
	Storage Storage

	// ErrColl is used to collect errors during refreshes.
	ErrColl errcoll.Interface

	// Metrics is used for the collection of the user profiles statistics.
	Metrics Metrics

	// CacheFilePath is the path to the profile cache file.  If cacheFilePath is
	// the string "none", filesystem cache is disabled.
	CacheFilePath string

	// FullSyncIvl is the interval between two full synchronizations with the
	// storage.
	FullSyncIvl time.Duration

	// FullSyncRetryIvl is the interval between two retries of full
	// synchronizations with the storage.
	FullSyncRetryIvl time.Duration

	// ResponseSizeEstimate is the estimate of the size of one DNS response for
	// the purposes of custom ratelimiting.  Responses over this estimate are
	// counted as several responses.
	ResponseSizeEstimate datasize.ByteSize
}

// Default is the default in-memory implementation of the [Interface] interface
// that can refresh itself from the provided storage.  It should be initially
// refreshed before use.
type Default struct {
	logger *slog.Logger

	// mapsMu protects the profiles, devices, deviceIDToProfileID,
	// dedicatedIPToDeviceID, humanIDToDeviceID, and linkedIPToDeviceID maps.
	mapsMu *sync.RWMutex

	// refreshMu serializes Refresh calls and access to all values used inside
	// of it.
	refreshMu *sync.Mutex

	// errColl is used to collect errors during refreshes.
	errColl errcoll.Interface

	// metrics is used for the collection of the user profiles statistics.
	metrics Metrics

	// cache is the filesystem-cache storage used by this profile database.
	cache internal.FileCacheStorage

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
// The initial refresh is performed immediately with the given timeout, beyond
// which an empty profiledb is returned.  If cacheFilePath is the string "none",
// filesystem cache is disabled.  db is not nil if the error is from getting the
// file cache.
func New(c *Config) (db *Default, err error) {
	var cacheStorage internal.FileCacheStorage
	if c.CacheFilePath == "none" {
		cacheStorage = internal.EmptyFileCacheStorage{}
	} else if ext := filepath.Ext(c.CacheFilePath); ext == ".pb" {
		cacheStorage = filecachepb.New(&filecachepb.Config{
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
		errColl:               c.ErrColl,
		metrics:               c.Metrics,
		cache:                 cacheStorage,
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
//
// TODO(a.garipov): Consider splitting the full refresh logic into a separate
// method.
func (db *Default) Refresh(ctx context.Context) (err error) {
	db.logger.DebugContext(ctx, "refresh started")
	defer db.logger.DebugContext(ctx, "refresh finished")

	sinceLastAttempt, isFullSync := db.needsFullSync(ctx)

	var profNum, devNum uint
	startTime := time.Now()
	defer func() {
		dur := time.Since(startTime)

		isSuccess := err == nil
		if !isSuccess {
			errcoll.Collect(ctx, db.errColl, db.logger, "refreshing profiledb", err)
		}

		db.metrics.HandleProfilesUpdate(ctx, &UpdateMetrics{
			ProfilesNum: profNum,
			DevicesNum:  devNum,
			Duration:    dur,
			IsSuccess:   isSuccess,
			IsFullSync:  isFullSync,
		})
	}()

	reqID := agd.NewRequestID()
	ctx = agd.WithRequestID(ctx, reqID)

	defer func() { err = errors.Annotate(err, "req %s: %w", reqID) }()

	db.refreshMu.Lock()
	defer db.refreshMu.Unlock()

	defer func() {
		db.metrics.SetProfilesAndDevicesNum(ctx, uint(len(db.profiles)), uint(len(db.devices)))
	}()

	resp, err := db.fetchProfiles(ctx, sinceLastAttempt, isFullSync)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	profiles := resp.Profiles
	devices := resp.Devices
	profNum = uint(len(profiles))
	devNum = uint(len(devices))

	db.logger.DebugContext(
		ctx,
		"storage request finished",
		"req_id", reqID,
		"prof_num", profNum,
		"dev_num", devNum,
	)

	db.setProfiles(ctx, profiles, devices, isFullSync)

	db.syncTime = resp.SyncTime
	if isFullSync {
		db.lastFullSync = time.Now()
		db.lastFullSyncError = time.Time{}

		err = db.cache.Store(ctx, &internal.FileCache{
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
) (sr *StorageProfilesResponse, err error) {
	syncTime := db.syncTime
	if isFullSync {
		db.logger.InfoContext(ctx, "full sync", "since_last_attempt", sinceLastAttempt)

		syncTime = time.Time{}
	}

	sr, err = db.storage.Profiles(ctx, &StorageProfilesRequest{
		SyncTime: syncTime,
	})
	if err == nil {
		return sr, nil
	}

	if isFullSync {
		db.lastFullSyncError = time.Now()
	}

	if errors.Is(err, context.DeadlineExceeded) {
		db.metrics.IncrementSyncTimeouts(ctx, isFullSync)
	}

	return nil, fmt.Errorf("updating profiles: %w", err)
}

// needsFullSync determines if a full synchronization is necessary.  If the last
// full synchronization was successful, it returns true if it's time for a new
// one.  Otherwise, it returns true if it's time for a retry.
func (db *Default) needsFullSync(ctx context.Context) (sinceFull time.Duration, isFull bool) {
	lastFull := db.lastFullSync
	sinceFull = time.Since(lastFull)
	if db.lastFullSyncError.IsZero() {
		return sinceFull, sinceFull >= db.fullSyncIvl
	}

	db.logger.WarnContext(
		ctx,
		"previous sync finished with error",
		"since_last_successful_sync", sinceFull,
		"last_successful_sync_time", lastFull,
	)

	sinceLastError := time.Since(db.lastFullSyncError)

	return sinceLastError, sinceLastError >= db.fullSyncRetryIvl
}

// loadFileCache loads the profiles data from the filesystem cache.
func (db *Default) loadFileCache(ctx context.Context) (err error) {
	start := time.Now()

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

	db.setProfiles(ctx, c.Profiles, c.Devices, true)
	db.syncTime, db.lastFullSync = c.SyncTime, c.SyncTime

	return nil
}

// setProfiles adds or updates the data for all profiles and devices.
func (db *Default) setProfiles(
	ctx context.Context,
	profiles []*agd.Profile,
	devices []*agd.Device,
	isFullSync bool,
) {
	db.mapsMu.Lock()
	defer db.mapsMu.Unlock()

	if isFullSync {
		clear(db.profiles)
		clear(db.devices)
		clear(db.dedicatedIPToDeviceID)
		clear(db.deviceIDToProfileID)
		clear(db.humanIDToDeviceID)
		clear(db.linkedIPToDeviceID)
	}

	for _, p := range profiles {
		db.profiles[p.ID] = p

		for _, devID := range p.DeviceIDs {
			db.deviceIDToProfileID[devID] = p.ID
		}

		if p.Deleted {
			// The deleted profiles are included in profiles slice only if
			// setProfiles is called when loading from the storage and it is not
			// a full sync.  If setProfiles is called when loading from cache,
			// the profiles slice does not include the deleted profiles, so we
			// can update metric correctly.
			db.metrics.IncrementDeleted(ctx)
		}
	}

	db.setDevices(ctx, devices)
}

// setDevices adds or updates the data for the given devices.  It assumes that
// db.mapsMu is locked for writing.
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
// if found.  It assumes that db.mapsMu is locked for reading.
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
	for _, profDevID := range p.DeviceIDs {
		if profDevID == id {
			d = db.devices[id]

			break
		}
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
