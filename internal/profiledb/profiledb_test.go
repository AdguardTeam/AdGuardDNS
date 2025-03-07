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
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Common IPs for tests
var (
	testClientIPv4      = netip.MustParseAddr("192.0.2.1")
	testOtherClientIPv4 = netip.MustParseAddr("192.0.2.2")

	testDedicatedIPv4      = netip.MustParseAddr("192.0.2.3")
	testOtherDedicatedIPv4 = netip.MustParseAddr("192.0.2.4")
)

// testTimeout is the common timeout for tests.
const testTimeout = 1 * time.Second

// testLogger is the common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

// newDefaultProfileDB returns a new default profile database for tests.
// devicesCh receives the devices that the storage should return in its
// response.
func newDefaultProfileDB(tb testing.TB, devices <-chan []*agd.Device) (db *profiledb.Default) {
	tb.Helper()

	onProfiles := func(
		_ context.Context,
		_ *profiledb.StorageProfilesRequest,
	) (resp *profiledb.StorageProfilesResponse, err error) {
		devices, _ := testutil.RequireReceive(tb, devices, testTimeout)
		devIDs := make([]agd.DeviceID, 0, len(devices))
		for _, d := range devices {
			devIDs = append(devIDs, d.ID)
		}

		return &profiledb.StorageProfilesResponse{
			Profiles: []*agd.Profile{{
				BlockingMode: &dnsmsg.BlockingModeNullIP{},
				ID:           profiledbtest.ProfileID,
				DeviceIDs:    devIDs,
			}},
			Devices: devices,
		}, nil
	}

	ps := &agdtest.ProfileStorage{
		OnCreateAutoDevice: func(
			_ context.Context,
			_ *profiledb.StorageCreateAutoDeviceRequest,
		) (resp *profiledb.StorageCreateAutoDeviceResponse, err error) {
			panic("not implemented")
		},
		OnProfiles: onProfiles,
	}

	db, err := profiledb.New(&profiledb.Config{
		Logger:               testLogger,
		BaseCustomLogger:     testLogger,
		Storage:              ps,
		ErrColl:              agdtest.NewErrorCollector(),
		Metrics:              profiledb.EmptyMetrics{},
		CacheFilePath:        "none",
		FullSyncIvl:          1 * time.Minute,
		FullSyncRetryIvl:     1 * time.Minute,
		ResponseSizeEstimate: profiledbtest.RespSzEst,
	})
	require.NoError(tb, err)

	ctx := testutil.ContextWithTimeout(tb, testTimeout)
	require.NoError(tb, db.Refresh(ctx))

	return db
}

func TestDefaultProfileDB(t *testing.T) {
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

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		p, d, err := db.ProfileByDedicatedIP(ctx, testDedicatedIPv4)
		require.NoError(t, err)

		assert.Equal(t, profiledbtest.ProfileID, p.ID)
		assert.Equal(t, d, devices[devIdxDefault])
	})

	t.Run("by_device_id", func(t *testing.T) {
		t.Parallel()

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		p, d, err := db.ProfileByDeviceID(ctx, profiledbtest.DeviceID)
		require.NoError(t, err)

		assert.Equal(t, profiledbtest.ProfileID, p.ID)
		assert.Equal(t, d, devices[devIdxDefault])
	})

	t.Run("by_human_id", func(t *testing.T) {
		t.Parallel()

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		p, d, err := db.ProfileByHumanID(ctx, profiledbtest.ProfileID, profiledbtest.HumanIDLower)
		require.NoError(t, err)

		assert.Equal(t, profiledbtest.ProfileID, p.ID)
		assert.Equal(t, d, devices[devIdxAuto])
	})

	t.Run("by_linked_ip", func(t *testing.T) {
		t.Parallel()

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		p, d, err := db.ProfileByLinkedIP(ctx, testClientIPv4)
		require.NoError(t, err)

		assert.Equal(t, profiledbtest.ProfileID, p.ID)
		assert.Equal(t, d, devices[devIdxDefault])
	})
}

func TestDefaultProfileDB_ProfileByDedicatedIP_removedDevice(t *testing.T) {
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

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	_, d, err := db.ProfileByDedicatedIP(ctx, testDedicatedIPv4)
	require.NoError(t, err)

	assert.Equal(t, d, dev)

	// The second response, the device is removed.
	devicesCh <- nil

	ctx = testutil.ContextWithTimeout(t, testTimeout)
	err = db.Refresh(ctx)
	require.NoError(t, err)

	assert.Eventually(t, func() (ok bool) {
		ctx = testutil.ContextWithTimeout(t, testTimeout)
		_, d, err = db.ProfileByDedicatedIP(ctx, testDedicatedIPv4)

		return errors.Is(err, profiledb.ErrDeviceNotFound)
	}, testTimeout, testTimeout/10)
}

func TestDefaultProfileDB_ProfileByDedicatedIP_deviceNewIP(t *testing.T) {
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
	}, testTimeout, testTimeout/10)
}

func TestDefaultProfileDB_ProfileByHumanID_removedDevice(t *testing.T) {
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
	}, testTimeout, testTimeout/10)
}

func TestDefaultProfileDB_ProfileByHumanID_deviceNotAuto(t *testing.T) {
	t.Parallel()

	dev := &agd.Device{
		ID:           profiledbtest.DeviceIDAuto,
		HumanIDLower: profiledbtest.HumanIDLower,
	}

	devicesCh := make(chan []*agd.Device, 2)

	// The first response, the device is still there.
	devicesCh <- []*agd.Device{dev}

	db := newDefaultProfileDB(t, devicesCh)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	_, d, err := db.ProfileByHumanID(ctx, profiledbtest.ProfileID, profiledbtest.HumanIDLower)
	require.NoError(t, err)

	assert.Equal(t, d, dev)

	// The second response, the device is now a non-auto device.
	devicesCh <- []*agd.Device{{
		ID: profiledbtest.DeviceIDAuto,
	}}

	ctx = testutil.ContextWithTimeout(t, testTimeout)
	err = db.Refresh(ctx)
	require.NoError(t, err)

	assert.Eventually(t, func() (ok bool) {
		ctx = testutil.ContextWithTimeout(t, testTimeout)
		_, d, err = db.ProfileByHumanID(ctx, profiledbtest.ProfileID, profiledbtest.HumanIDLower)

		return errors.Is(err, profiledb.ErrDeviceNotFound)
	}, testTimeout, testTimeout/10)
}

func TestDefaultProfileDB_ProfileByLinkedIP_removedDevice(t *testing.T) {
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
	}, testTimeout, testTimeout/10)
}

func TestDefaultProfileDB_ProfileByLinkedIP_deviceNewIP(t *testing.T) {
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
	}, testTimeout, testTimeout/10)
}

func TestDefaultProfileDB_fileCache_success(t *testing.T) {
	t.Parallel()

	var gotSyncTime time.Time
	onProfiles := func(
		_ context.Context,
		req *profiledb.StorageProfilesRequest,
	) (resp *profiledb.StorageProfilesResponse, err error) {
		gotSyncTime = req.SyncTime

		return &profiledb.StorageProfilesResponse{}, nil
	}

	ps := &agdtest.ProfileStorage{
		OnCreateAutoDevice: func(
			_ context.Context,
			_ *profiledb.StorageCreateAutoDeviceRequest,
		) (resp *profiledb.StorageCreateAutoDeviceResponse, err error) {
			panic("not implemented")
		},
		OnProfiles: onProfiles,
	}

	// Use the time with monotonic clocks stripped down.
	wantSyncTime := time.Now().Round(0).UTC()

	prof, dev := profiledbtest.NewProfile(t)

	cacheFilePath := filepath.Join(t.TempDir(), "profiles.pb")
	pbCache := filecachepb.New(&filecachepb.Config{
		Logger:               testLogger,
		BaseCustomLogger:     testLogger,
		CacheFilePath:        cacheFilePath,
		ResponseSizeEstimate: profiledbtest.RespSzEst,
	})

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	err := pbCache.Store(ctx, &internal.FileCache{
		SyncTime: wantSyncTime,
		Profiles: []*agd.Profile{prof},
		Devices:  []*agd.Device{dev},
		Version:  internal.FileCacheVersion,
	})
	require.NoError(t, err)

	db, err := profiledb.New(&profiledb.Config{
		Logger:               testLogger,
		BaseCustomLogger:     testLogger,
		Storage:              ps,
		ErrColl:              agdtest.NewErrorCollector(),
		Metrics:              profiledb.EmptyMetrics{},
		CacheFilePath:        cacheFilePath,
		FullSyncIvl:          1 * time.Minute,
		FullSyncRetryIvl:     1 * time.Minute,
		ResponseSizeEstimate: profiledbtest.RespSzEst,
	})
	require.NoError(t, err)
	require.NotNil(t, db)

	ctx = testutil.ContextWithTimeout(t, testTimeout)
	require.NoError(t, db.Refresh(ctx))

	assert.Equal(t, wantSyncTime, gotSyncTime)

	p, d, err := db.ProfileByDeviceID(context.Background(), dev.ID)
	require.NoError(t, err)
	assert.Equal(t, dev, d)
	assert.Equal(t, prof, p)
}

func TestDefaultProfileDB_fileCache_badVersion(t *testing.T) {
	t.Parallel()

	storageCalled := false
	ps := &agdtest.ProfileStorage{
		OnCreateAutoDevice: func(
			_ context.Context,
			_ *profiledb.StorageCreateAutoDeviceRequest,
		) (resp *profiledb.StorageCreateAutoDeviceResponse, err error) {
			panic("not implemented")
		},
		OnProfiles: func(
			_ context.Context,
			_ *profiledb.StorageProfilesRequest,
		) (resp *profiledb.StorageProfilesResponse, err error) {
			storageCalled = true

			return &profiledb.StorageProfilesResponse{}, nil
		},
	}

	cacheFilePath := filepath.Join(t.TempDir(), "profiles.pb")
	pbCache := filecachepb.New(&filecachepb.Config{
		Logger:               testLogger,
		BaseCustomLogger:     testLogger,
		CacheFilePath:        cacheFilePath,
		ResponseSizeEstimate: profiledbtest.RespSzEst,
	})

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	err := pbCache.Store(ctx, &internal.FileCache{
		Version: 10000,
	})
	require.NoError(t, err)

	db, err := profiledb.New(&profiledb.Config{
		Logger:               testLogger,
		BaseCustomLogger:     testLogger,
		Storage:              ps,
		ErrColl:              agdtest.NewErrorCollector(),
		Metrics:              profiledb.EmptyMetrics{},
		CacheFilePath:        cacheFilePath,
		FullSyncIvl:          1 * time.Minute,
		FullSyncRetryIvl:     1 * time.Minute,
		ResponseSizeEstimate: profiledbtest.RespSzEst,
	})
	assert.NoError(t, err)
	assert.NotNil(t, db)

	ctx = testutil.ContextWithTimeout(t, testTimeout)
	require.NoError(t, db.Refresh(ctx))

	assert.True(t, storageCalled)
}

func TestDefaultProfileDB_CreateAutoDevice(t *testing.T) {
	t.Parallel()

	wantDev := &agd.Device{
		ID:           profiledbtest.DeviceIDAuto,
		HumanIDLower: profiledbtest.HumanIDLower,
	}
	wantProf := &agd.Profile{
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

	db, err := profiledb.New(&profiledb.Config{
		Logger:               testLogger,
		BaseCustomLogger:     testLogger,
		Storage:              ps,
		ErrColl:              agdtest.NewErrorCollector(),
		Metrics:              profiledb.EmptyMetrics{},
		CacheFilePath:        "none",
		FullSyncIvl:          1 * time.Minute,
		FullSyncRetryIvl:     1 * time.Minute,
		ResponseSizeEstimate: profiledbtest.RespSzEst,
	})
	require.NoError(t, err)
	require.NotNil(t, db)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
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

// Sinks for benchmarks.
var (
	profSink *agd.Profile
	devSink  *agd.Device
	errSink  error
)

func BenchmarkDefaultProfileDB_ProfileByDeviceID(b *testing.B) {
	dev := &agd.Device{
		ID: profiledbtest.DeviceID,
	}

	devicesCh := make(chan []*agd.Device, 1)
	devicesCh <- []*agd.Device{dev}
	db := newDefaultProfileDB(b, devicesCh)

	ctx := context.Background()

	b.Run("success", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			profSink, devSink, errSink = db.ProfileByDeviceID(ctx, profiledbtest.DeviceID)
		}

		assert.NotNil(b, profSink)
		assert.NotNil(b, devSink)
		assert.NoError(b, errSink)
	})

	const wrongDevID = profiledbtest.DeviceID + "_bad"

	b.Run("not_found", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			profSink, devSink, errSink = db.ProfileByDeviceID(ctx, wrongDevID)
		}

		assert.Nil(b, profSink)
		assert.Nil(b, devSink)
		assert.ErrorIs(b, errSink, profiledb.ErrDeviceNotFound)
	})

	// Most recent results, as of 2023-04-10, on a ThinkPad X13 with a Ryzen Pro
	// 7 CPU:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/profiledb
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDefaultProfileDB_ProfileByDeviceID/success-16         	55459413	        23.43 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkDefaultProfileDB_ProfileByDeviceID/not_found-16       	61798608	        17.87 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkDefaultProfileDB_ProfileByLinkedIP(b *testing.B) {
	dev := &agd.Device{
		ID:       profiledbtest.DeviceID,
		LinkedIP: testClientIPv4,
	}

	devicesCh := make(chan []*agd.Device, 1)
	devicesCh <- []*agd.Device{dev}
	db := newDefaultProfileDB(b, devicesCh)

	ctx := context.Background()

	b.Run("success", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			profSink, devSink, errSink = db.ProfileByLinkedIP(ctx, testClientIPv4)
		}

		assert.NotNil(b, profSink)
		assert.NotNil(b, devSink)
		assert.NoError(b, errSink)
	})

	b.Run("not_found", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			profSink, devSink, errSink = db.ProfileByLinkedIP(ctx, testOtherClientIPv4)
		}

		assert.Nil(b, profSink)
		assert.Nil(b, devSink)
		assert.ErrorIs(b, errSink, profiledb.ErrDeviceNotFound)
	})

	// Most recent results, as of 2023-04-10, on a ThinkPad X13 with a Ryzen Pro
	// 7 CPU:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/profiledb
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDefaultProfileDB_ProfileByLinkedIP/success-16         	26068507	        44.23 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkDefaultProfileDB_ProfileByLinkedIP/not_found-16       	53764724	        22.63 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkDefaultProfileDB_ProfileByDedicatedIP(b *testing.B) {
	dev := &agd.Device{
		ID: profiledbtest.DeviceID,
		DedicatedIPs: []netip.Addr{
			testClientIPv4,
		},
	}

	devicesCh := make(chan []*agd.Device, 1)
	devicesCh <- []*agd.Device{dev}
	db := newDefaultProfileDB(b, devicesCh)

	ctx := context.Background()

	b.Run("success", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			profSink, devSink, errSink = db.ProfileByDedicatedIP(ctx, testClientIPv4)
		}

		assert.NotNil(b, profSink)
		assert.NotNil(b, devSink)
		assert.NoError(b, errSink)
	})

	b.Run("not_found", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			profSink, devSink, errSink = db.ProfileByDedicatedIP(ctx, testOtherClientIPv4)
		}

		assert.Nil(b, profSink)
		assert.Nil(b, devSink)
		assert.ErrorIs(b, errSink, profiledb.ErrDeviceNotFound)
	})

	// Most recent results, as of 2023-04-10, on a ThinkPad X13 with a Ryzen Pro
	// 7 CPU:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/profiledb
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDefaultProfileDB_ProfileByDedicatedIP/success-16      	26034816	        48.21 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkDefaultProfileDB_ProfileByDedicatedIP/not_found-16    	54165615	        22.38 ns/op	       0 B/op	       0 allocs/op
}
