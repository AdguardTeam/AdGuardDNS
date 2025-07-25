package profiledb_test

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/filecachepb"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/profiledbtest"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault(t *testing.T) {
	t.Parallel()

	const (
		devIdxDefault = iota
		devIdxAuto
	)

	devices := []*agd.Device{
		devIdxDefault: {
			ID:       profiledbtest.DeviceID,
			LinkedIP: testClientIPv4,
			DedicatedIPs: []netip.Addr{
				testDedicatedIPv4,
			},
		},
		devIdxAuto: {
			ID:           profiledbtest.DeviceIDAuto,
			HumanIDLower: profiledbtest.HumanIDLower,
		},
	}

	devicesCh := make(chan []*agd.Device, 2)
	devicesCh <- devices
	db := newDefaultProfileDB(t, devicesCh)

	t.Run("by_dedicated_ip", func(t *testing.T) {
		t.Parallel()

		ctx := profiledbtest.ContextWithTimeout(t)
		p, d, err := db.ProfileByDedicatedIP(ctx, testDedicatedIPv4)
		require.NoError(t, err)

		assert.Equal(t, profiledbtest.ProfileID, p.ID)
		assert.Equal(t, d, devices[devIdxDefault])
	})

	t.Run("by_device_id", func(t *testing.T) {
		t.Parallel()

		ctx := profiledbtest.ContextWithTimeout(t)
		p, d, err := db.ProfileByDeviceID(ctx, profiledbtest.DeviceID)
		require.NoError(t, err)

		assert.Equal(t, profiledbtest.ProfileID, p.ID)
		assert.Equal(t, d, devices[devIdxDefault])
	})

	t.Run("by_human_id", func(t *testing.T) {
		t.Parallel()

		ctx := profiledbtest.ContextWithTimeout(t)
		p, d, err := db.ProfileByHumanID(ctx, profiledbtest.ProfileID, profiledbtest.HumanIDLower)
		require.NoError(t, err)

		assert.Equal(t, profiledbtest.ProfileID, p.ID)
		assert.Equal(t, d, devices[devIdxAuto])
	})

	t.Run("by_linked_ip", func(t *testing.T) {
		t.Parallel()

		ctx := profiledbtest.ContextWithTimeout(t)
		p, d, err := db.ProfileByLinkedIP(ctx, testClientIPv4)
		require.NoError(t, err)

		assert.Equal(t, profiledbtest.ProfileID, p.ID)
		assert.Equal(t, d, devices[devIdxDefault])
	})
}

func TestDefault_ProfileByDedicatedIP_removedDevice(t *testing.T) {
	t.Parallel()

	dev := &agd.Device{
		ID: profiledbtest.DeviceID,
		DedicatedIPs: []netip.Addr{
			testDedicatedIPv4,
		},
	}

	devicesCh := make(chan []*agd.Device, 2)

	// The first response, the device is still there.
	devicesCh <- []*agd.Device{dev}

	db := newDefaultProfileDB(t, devicesCh)

	ctx := profiledbtest.ContextWithTimeout(t)
	_, d, err := db.ProfileByDedicatedIP(ctx, testDedicatedIPv4)
	require.NoError(t, err)

	assert.Equal(t, d, dev)

	// The second response, the device is removed.
	devicesCh <- nil

	ctx = profiledbtest.ContextWithTimeout(t)
	err = db.Refresh(ctx)
	require.NoError(t, err)

	assert.Eventually(t, func() (ok bool) {
		ctx = profiledbtest.ContextWithTimeout(t)
		_, d, err = db.ProfileByDedicatedIP(ctx, testDedicatedIPv4)

		return errors.Is(err, profiledb.ErrDeviceNotFound)
	}, profiledbtest.Timeout, profiledbtest.Timeout/10)
}

func TestDefault_ProfileByDedicatedIP_deviceNewIP(t *testing.T) {
	t.Parallel()

	dev := &agd.Device{
		ID: profiledbtest.DeviceID,
		DedicatedIPs: []netip.Addr{
			testDedicatedIPv4,
		},
	}

	devicesCh := make(chan []*agd.Device, 2)

	// The first response, the device is still there.
	devicesCh <- []*agd.Device{dev}

	db := newDefaultProfileDB(t, devicesCh)

	ctx := context.Background()
	_, d, err := db.ProfileByDedicatedIP(ctx, testDedicatedIPv4)
	require.NoError(t, err)

	assert.Equal(t, d, dev)

	// The second response, the device has a new IP.
	dev.DedicatedIPs[0] = testOtherDedicatedIPv4
	devicesCh <- []*agd.Device{dev}

	err = db.Refresh(ctx)
	require.NoError(t, err)

	assert.Eventually(t, func() (ok bool) {
		_, _, err = db.ProfileByDedicatedIP(ctx, testDedicatedIPv4)

		if !errors.Is(err, profiledb.ErrDeviceNotFound) {
			return false
		}

		_, d, err = db.ProfileByDedicatedIP(ctx, testOtherDedicatedIPv4)
		if err != nil {
			return false
		}

		return d != nil && d.ID == dev.ID
	}, profiledbtest.Timeout, profiledbtest.Timeout/10)
}

func TestDefault_ProfileByHumanID_removedDevice(t *testing.T) {
	t.Parallel()

	dev := &agd.Device{
		ID:           profiledbtest.DeviceIDAuto,
		HumanIDLower: profiledbtest.HumanIDLower,
	}

	devicesCh := make(chan []*agd.Device, 2)

	// The first response, the device is still there.
	devicesCh <- []*agd.Device{dev}

	db := newDefaultProfileDB(t, devicesCh)

	ctx := context.Background()
	_, d, err := db.ProfileByHumanID(ctx, profiledbtest.ProfileID, profiledbtest.HumanIDLower)
	require.NoError(t, err)

	assert.Equal(t, d, dev)

	// The second response, the device is removed.
	devicesCh <- nil

	err = db.Refresh(ctx)
	require.NoError(t, err)

	assert.Eventually(t, func() (ok bool) {
		_, d, err = db.ProfileByHumanID(ctx, profiledbtest.ProfileID, profiledbtest.HumanIDLower)

		return errors.Is(err, profiledb.ErrDeviceNotFound)
	}, profiledbtest.Timeout, profiledbtest.Timeout/10)
}

func TestDefault_ProfileByHumanID_deviceNotAuto(t *testing.T) {
	t.Parallel()

	dev := &agd.Device{
		ID:           profiledbtest.DeviceIDAuto,
		HumanIDLower: profiledbtest.HumanIDLower,
	}

	devicesCh := make(chan []*agd.Device, 2)

	// The first response, the device is still there.
	devicesCh <- []*agd.Device{dev}

	db := newDefaultProfileDB(t, devicesCh)

	ctx := profiledbtest.ContextWithTimeout(t)
	_, d, err := db.ProfileByHumanID(ctx, profiledbtest.ProfileID, profiledbtest.HumanIDLower)
	require.NoError(t, err)

	assert.Equal(t, d, dev)

	// The second response, the device is now a non-auto device.
	devicesCh <- []*agd.Device{{
		ID: profiledbtest.DeviceIDAuto,
	}}

	ctx = profiledbtest.ContextWithTimeout(t)
	err = db.Refresh(ctx)
	require.NoError(t, err)

	assert.Eventually(t, func() (ok bool) {
		ctx = profiledbtest.ContextWithTimeout(t)
		_, d, err = db.ProfileByHumanID(ctx, profiledbtest.ProfileID, profiledbtest.HumanIDLower)

		return errors.Is(err, profiledb.ErrDeviceNotFound)
	}, profiledbtest.Timeout, profiledbtest.Timeout/10)
}

func TestDefault_ProfileByLinkedIP_removedDevice(t *testing.T) {
	t.Parallel()

	dev := &agd.Device{
		ID:       profiledbtest.DeviceID,
		LinkedIP: testClientIPv4,
	}

	devicesCh := make(chan []*agd.Device, 2)

	// The first response, the device is still there.
	devicesCh <- []*agd.Device{dev}

	db := newDefaultProfileDB(t, devicesCh)

	ctx := context.Background()
	_, d, err := db.ProfileByLinkedIP(ctx, testClientIPv4)
	require.NoError(t, err)

	assert.Equal(t, d, dev)

	// The second response, the device is removed.
	devicesCh <- nil

	err = db.Refresh(ctx)
	require.NoError(t, err)

	assert.Eventually(t, func() (ok bool) {
		_, d, err = db.ProfileByLinkedIP(ctx, testClientIPv4)

		return errors.Is(err, profiledb.ErrDeviceNotFound)
	}, profiledbtest.Timeout, profiledbtest.Timeout/10)
}

func TestDefault_ProfileByLinkedIP_deviceNewIP(t *testing.T) {
	t.Parallel()

	dev := &agd.Device{
		ID:       profiledbtest.DeviceID,
		LinkedIP: testClientIPv4,
	}

	devicesCh := make(chan []*agd.Device, 2)

	// The first response, the device is still there.
	devicesCh <- []*agd.Device{dev}

	db := newDefaultProfileDB(t, devicesCh)

	ctx := context.Background()
	_, d, err := db.ProfileByLinkedIP(ctx, testClientIPv4)
	require.NoError(t, err)

	assert.Equal(t, d, dev)

	// The second response, the device has a new IP.
	dev.LinkedIP = testOtherClientIPv4
	devicesCh <- []*agd.Device{dev}

	err = db.Refresh(ctx)
	require.NoError(t, err)

	assert.Eventually(t, func() (ok bool) {
		_, _, err = db.ProfileByLinkedIP(ctx, testClientIPv4)

		if !errors.Is(err, profiledb.ErrDeviceNotFound) {
			return false
		}

		_, d, err = db.ProfileByLinkedIP(ctx, testOtherClientIPv4)
		if err != nil {
			return false
		}

		return d != nil && d.ID == dev.ID
	}, profiledbtest.Timeout, profiledbtest.Timeout/10)
}

func TestDefault_fileCache_success(t *testing.T) {
	t.Parallel()

	var gotSyncTime time.Time

	ps := agdtest.NewProfileStorage()
	ps.OnProfiles = func(
		_ context.Context,
		req *profiledb.StorageProfilesRequest,
	) (resp *profiledb.StorageProfilesResponse, err error) {
		gotSyncTime = req.SyncTime

		return &profiledb.StorageProfilesResponse{}, nil
	}

	// Use the time with monotonic clocks stripped down.
	wantSyncTime := time.Now().Round(0).UTC()

	prof, dev := profiledbtest.NewProfile(t)

	cacheFilePath := filepath.Join(t.TempDir(), "profiles.pb")
	pbCache := filecachepb.New(&filecachepb.Config{
		Logger:                   profiledbtest.Logger,
		BaseCustomLogger:         profiledbtest.Logger,
		ProfileAccessConstructor: profiledbtest.ProfileAccessConstructor,
		CacheFilePath:            cacheFilePath,
		ResponseSizeEstimate:     profiledbtest.RespSzEst,
	})

	ctx := profiledbtest.ContextWithTimeout(t)
	err := pbCache.Store(ctx, &internal.FileCache{
		SyncTime: wantSyncTime,
		Profiles: []*agd.Profile{prof},
		Devices:  []*agd.Device{dev},
		Version:  internal.FileCacheVersion,
	})
	require.NoError(t, err)

	db := newProfileDB(t, &profiledb.Config{
		Storage:       ps,
		CacheFilePath: cacheFilePath,
	})

	ctx = profiledbtest.ContextWithTimeout(t)
	require.NoError(t, db.Refresh(ctx))

	assert.Equal(t, wantSyncTime, gotSyncTime)

	p, d, err := db.ProfileByDeviceID(context.Background(), dev.ID)
	require.NoError(t, err)
	assert.Equal(t, dev, d)
	assert.Equal(t, prof, p)
}

func TestDefault_fileCache_badVersion(t *testing.T) {
	t.Parallel()

	storageCalled := false
	ps := agdtest.NewProfileStorage()
	ps.OnProfiles = func(
		_ context.Context,
		_ *profiledb.StorageProfilesRequest,
	) (resp *profiledb.StorageProfilesResponse, err error) {
		storageCalled = true

		return &profiledb.StorageProfilesResponse{}, nil
	}

	cacheFilePath := filepath.Join(t.TempDir(), "profiles.pb")
	pbCache := filecachepb.New(&filecachepb.Config{
		Logger:                   profiledbtest.Logger,
		BaseCustomLogger:         profiledbtest.Logger,
		ProfileAccessConstructor: profiledbtest.ProfileAccessConstructor,
		CacheFilePath:            cacheFilePath,
		ResponseSizeEstimate:     profiledbtest.RespSzEst,
	})

	ctx := profiledbtest.ContextWithTimeout(t)
	err := pbCache.Store(ctx, &internal.FileCache{
		Version: 10000,
	})
	require.NoError(t, err)

	db := newProfileDB(t, &profiledb.Config{
		Storage:       ps,
		CacheFilePath: cacheFilePath,
	})

	ctx = profiledbtest.ContextWithTimeout(t)
	require.NoError(t, db.Refresh(ctx))

	assert.True(t, storageCalled)
}

func TestDefault_CreateAutoDevice(t *testing.T) {
	t.Parallel()

	wantDev := &agd.Device{
		ID:           profiledbtest.DeviceIDAuto,
		HumanIDLower: profiledbtest.HumanIDLower,
	}
	wantProf := &agd.Profile{
		CustomDomains:      &agd.AccountCustomDomains{},
		BlockingMode:       &dnsmsg.BlockingModeNullIP{},
		ID:                 profiledbtest.ProfileID,
		DeviceIDs:          nil,
		AutoDevicesEnabled: true,
	}

	ps := &agdtest.ProfileStorage{
		OnCreateAutoDevice: func(
			_ context.Context,
			_ *profiledb.StorageCreateAutoDeviceRequest,
		) (resp *profiledb.StorageCreateAutoDeviceResponse, err error) {
			return &profiledb.StorageCreateAutoDeviceResponse{
				Device: wantDev,
			}, nil
		},
		OnProfiles: func(
			_ context.Context,
			_ *profiledb.StorageProfilesRequest,
		) (resp *profiledb.StorageProfilesResponse, err error) {
			return &profiledb.StorageProfilesResponse{
				Profiles: []*agd.Profile{wantProf},
				Devices:  nil,
			}, nil
		},
	}

	db := newProfileDB(t, &profiledb.Config{
		Storage: ps,
	})

	ctx := profiledbtest.ContextWithTimeout(t)
	require.NoError(t, db.Refresh(ctx))

	p, d, err := db.CreateAutoDevice(
		ctx,
		profiledbtest.ProfileID,
		profiledbtest.HumanID,
		agd.DeviceTypeOther,
	)
	require.NoError(t, err)

	assert.Equal(t, wantDev, d)
	assert.Equal(t, wantProf, p)
}

func TestDefault_deviceChanges(t *testing.T) {
	t.Parallel()

	var (
		devPrevName = &agd.Device{
			ID:   profiledbtest.DeviceID,
			Name: "Name 1",
		}

		devNewName = &agd.Device{
			ID:   profiledbtest.DeviceID,
			Name: "Name 2",
		}

		devAuto = &agd.Device{
			ID:           profiledbtest.DeviceIDAuto,
			HumanIDLower: profiledbtest.HumanIDLower,
		}
	)

	profBefore := &agd.Profile{
		CustomDomains: &agd.AccountCustomDomains{},
		BlockingMode:  &dnsmsg.BlockingModeNullIP{},
		ID:            profiledbtest.ProfileID,
		DeviceIDs: container.NewMapSet(
			profiledbtest.DeviceID,
			profiledbtest.DeviceIDAuto,
		),
		AutoDevicesEnabled: true,
	}

	profAfter := &agd.Profile{
		CustomDomains: &agd.AccountCustomDomains{},
		BlockingMode:  &dnsmsg.BlockingModeNullIP{},
		ID:            profiledbtest.ProfileID,
		DeviceIDs: container.NewMapSet(
			profiledbtest.DeviceID,
		),
		AutoDevicesEnabled: true,
	}

	var (
		strgRespFull = &profiledb.StorageProfilesResponse{
			SyncTime: time.Now(),
			Profiles: []*agd.Profile{profBefore},
			Devices:  []*agd.Device{devPrevName, devAuto},
		}

		strgRespChg = &profiledb.StorageDeviceChange{
			DeletedDeviceIDs: []agd.DeviceID{profiledbtest.DeviceIDAuto},
			IsPartial:        true,
		}

		strgRespPartial = &profiledb.StorageProfilesResponse{
			SyncTime: time.Now(),
			DeviceChanges: map[agd.ProfileID]*profiledb.StorageDeviceChange{
				profiledbtest.ProfileID: strgRespChg,
			},
			Profiles: []*agd.Profile{profAfter},
			Devices:  []*agd.Device{devNewName},
		}
	)

	ps := agdtest.NewProfileStorage()
	ps.OnProfiles = func(
		_ context.Context,
		req *profiledb.StorageProfilesRequest,
	) (resp *profiledb.StorageProfilesResponse, err error) {
		if req.SyncTime.IsZero() {
			return strgRespFull, nil
		} else {
			return strgRespPartial, nil
		}
	}

	db := newProfileDB(t, &profiledb.Config{
		Storage: ps,
	})

	require.True(t, t.Run("after_full", func(t *testing.T) {
		ctx := profiledbtest.ContextWithTimeout(t)
		require.NoError(t, db.RefreshFull(ctx))

		ctx = profiledbtest.ContextWithTimeout(t)
		p, d, dbErr := db.ProfileByDeviceID(ctx, profiledbtest.DeviceID)
		require.NoError(t, dbErr)

		assert.Equal(t, profBefore, p)
		assert.Equal(t, devPrevName, d)

		ctx = profiledbtest.ContextWithTimeout(t)
		p, d, dbErr = db.ProfileByDeviceID(ctx, profiledbtest.DeviceIDAuto)
		require.NoError(t, dbErr)

		assert.Equal(t, profBefore, p)
		assert.Equal(t, devAuto, d)
	}))

	require.True(t, t.Run("after_partial", func(t *testing.T) {
		ctx := profiledbtest.ContextWithTimeout(t)
		require.NoError(t, db.Refresh(ctx))

		ctx = profiledbtest.ContextWithTimeout(t)
		p, d, dbErr := db.ProfileByDeviceID(ctx, profiledbtest.DeviceID)
		require.NoError(t, dbErr)

		assert.Equal(t, profAfter, p)
		assert.Equal(t, devNewName, d)

		ctx = profiledbtest.ContextWithTimeout(t)
		p, d, dbErr = db.ProfileByDeviceID(ctx, profiledbtest.DeviceIDAuto)
		assert.ErrorIs(t, dbErr, profiledb.ErrDeviceNotFound)
		assert.Nil(t, p)
		assert.Nil(t, d)
	}))
}

func TestDefault_noDeviceChanges(t *testing.T) {
	t.Parallel()

	dev := &agd.Device{
		ID: profiledbtest.DeviceID,
	}

	profBefore := &agd.Profile{
		CustomDomains:    &agd.AccountCustomDomains{},
		BlockingMode:     &dnsmsg.BlockingModeNullIP{},
		ID:               profiledbtest.ProfileID,
		FilteringEnabled: true,
		DeviceIDs:        container.NewMapSet(profiledbtest.DeviceID),
	}

	profAfter := &agd.Profile{
		CustomDomains:    &agd.AccountCustomDomains{},
		BlockingMode:     &dnsmsg.BlockingModeNullIP{},
		ID:               profiledbtest.ProfileID,
		FilteringEnabled: false,
		DeviceIDs:        container.NewMapSet(profiledbtest.DeviceID),
	}

	var (
		strgRespFull = &profiledb.StorageProfilesResponse{
			SyncTime: time.Now(),
			Profiles: []*agd.Profile{profBefore},
			Devices:  []*agd.Device{dev},
		}

		strgRespChg = &profiledb.StorageDeviceChange{
			DeletedDeviceIDs: []agd.DeviceID{},
			IsPartial:        true,
		}

		strgRespPartial = &profiledb.StorageProfilesResponse{
			SyncTime: time.Now(),
			DeviceChanges: map[agd.ProfileID]*profiledb.StorageDeviceChange{
				profiledbtest.ProfileID: strgRespChg,
			},
			Profiles: []*agd.Profile{profAfter},
			Devices:  []*agd.Device{},
		}
	)

	ps := agdtest.NewProfileStorage()
	ps.OnProfiles = func(
		_ context.Context,
		req *profiledb.StorageProfilesRequest,
	) (resp *profiledb.StorageProfilesResponse, err error) {
		if req.SyncTime.IsZero() {
			return strgRespFull, nil
		} else {
			return strgRespPartial, nil
		}
	}

	db := newProfileDB(t, &profiledb.Config{
		Storage: ps,
	})

	require.True(t, t.Run("after_full", func(t *testing.T) {
		ctx := profiledbtest.ContextWithTimeout(t)
		require.NoError(t, db.RefreshFull(ctx))

		ctx = profiledbtest.ContextWithTimeout(t)
		p, d, dbErr := db.ProfileByDeviceID(ctx, profiledbtest.DeviceID)
		require.NoError(t, dbErr)

		assert.Equal(t, profBefore, p)
		assert.Equal(t, dev, d)
	}))

	require.True(t, t.Run("after_partial", func(t *testing.T) {
		ctx := profiledbtest.ContextWithTimeout(t)
		require.NoError(t, db.Refresh(ctx))

		ctx = profiledbtest.ContextWithTimeout(t)
		p, d, dbErr := db.ProfileByDeviceID(ctx, profiledbtest.DeviceID)
		require.NoError(t, dbErr)

		assert.Equal(t, profAfter, p)
		assert.Equal(t, dev, d)
	}))
}

func BenchmarkDefault_ProfileByDeviceID(b *testing.B) {
	existingDev := &agd.Device{
		ID: profiledbtest.DeviceID,
	}

	devicesCh := make(chan []*agd.Device, 1)
	devicesCh <- []*agd.Device{existingDev}
	db := newDefaultProfileDB(b, devicesCh)

	ctx := context.Background()

	var (
		prof *agd.Profile
		dev  *agd.Device
		err  error
	)

	b.Run("success", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			prof, dev, err = db.ProfileByDeviceID(ctx, profiledbtest.DeviceID)
		}

		assert.NotNil(b, prof)
		assert.NotNil(b, dev)
		assert.NoError(b, err)
	})

	const wrongDevID = profiledbtest.DeviceID + "_bad"

	b.Run("not_found", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			prof, dev, err = db.ProfileByDeviceID(ctx, wrongDevID)
		}

		assert.Nil(b, prof)
		assert.Nil(b, dev)
		assert.ErrorIs(b, err, profiledb.ErrDeviceNotFound)
	})

	// Most recent results:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/profiledb
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDefault_ProfileByDeviceID/success-16         	31104525	        37.61 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkDefault_ProfileByDeviceID/not_found-16       	60978588	        18.41 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkDefault_ProfileByLinkedIP(b *testing.B) {
	existingDev := &agd.Device{
		ID:       profiledbtest.DeviceID,
		LinkedIP: testClientIPv4,
	}

	devicesCh := make(chan []*agd.Device, 1)
	devicesCh <- []*agd.Device{existingDev}
	db := newDefaultProfileDB(b, devicesCh)

	ctx := context.Background()

	var (
		prof *agd.Profile
		dev  *agd.Device
		err  error
	)

	b.Run("success", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			prof, dev, err = db.ProfileByLinkedIP(ctx, testClientIPv4)
		}

		assert.NotNil(b, prof)
		assert.NotNil(b, dev)
		assert.NoError(b, err)
	})

	b.Run("not_found", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			prof, dev, err = db.ProfileByLinkedIP(ctx, testOtherClientIPv4)
		}

		assert.Nil(b, prof)
		assert.Nil(b, dev)
		assert.ErrorIs(b, err, profiledb.ErrDeviceNotFound)
	})

	// Most recent results:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/profiledb
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDefault_ProfileByLinkedIP/success-16         	18498074	        63.25 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkDefault_ProfileByLinkedIP/not_found-16       	46330509	        23.94 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkDefault_ProfileByDedicatedIP(b *testing.B) {
	existingDev := &agd.Device{
		ID: profiledbtest.DeviceID,
		DedicatedIPs: []netip.Addr{
			testClientIPv4,
		},
	}

	devicesCh := make(chan []*agd.Device, 1)
	devicesCh <- []*agd.Device{existingDev}
	db := newDefaultProfileDB(b, devicesCh)

	ctx := context.Background()

	var (
		prof *agd.Profile
		dev  *agd.Device
		err  error
	)

	b.Run("success", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			prof, dev, err = db.ProfileByDedicatedIP(ctx, testClientIPv4)
		}

		assert.NotNil(b, prof)
		assert.NotNil(b, dev)
		assert.NoError(b, err)
	})

	b.Run("not_found", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			prof, dev, err = db.ProfileByDedicatedIP(ctx, testOtherClientIPv4)
		}

		assert.Nil(b, prof)
		assert.Nil(b, dev)
		assert.ErrorIs(b, err, profiledb.ErrDeviceNotFound)
	})

	// Most recent results:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/profiledb
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDefault_ProfileByDedicatedIP/success-16         	18668960	        63.51 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkDefault_ProfileByDedicatedIP/not_found-16       	57252513	        19.94 ns/op	       0 B/op	       0 allocs/op
}
