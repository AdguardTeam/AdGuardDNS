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
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// Common IPs for tests
var (
	testClientIPv4      = netip.MustParseAddr("1.2.3.4")
	testOtherClientIPv4 = netip.MustParseAddr("1.2.3.5")

	testDedicatedIPv4      = netip.MustParseAddr("1.2.4.5")
	testOtherDedicatedIPv4 = netip.MustParseAddr("1.2.4.6")
)

// testTimeout is the common timeout for tests.
const testTimeout = 1 * time.Second

// newDefaultProfileDB returns a new default profile database for tests.
// devicesCh receives the devices that the storage should return in its
// response.
func newDefaultProfileDB(tb testing.TB, devices <-chan []*agd.Device) (db *profiledb.Default) {
	tb.Helper()

	onProfiles := func(
		_ context.Context,
		_ *profiledb.StorageRequest,
	) (resp *profiledb.StorageResponse, err error) {
		devices, _ := testutil.RequireReceive(tb, devices, testTimeout)
		devIDs := make([]agd.DeviceID, 0, len(devices))
		for _, d := range devices {
			devIDs = append(devIDs, d.ID)
		}

		return &profiledb.StorageResponse{
			Profiles: []*agd.Profile{{
				BlockingMode: dnsmsg.BlockingModeCodec{
					Mode: &dnsmsg.BlockingModeNullIP{},
				},
				ID:        profiledbtest.ProfileID,
				DeviceIDs: devIDs,
			}},
			Devices: devices,
		}, nil
	}

	ps := &agdtest.ProfileStorage{
		OnProfiles: onProfiles,
	}

	db, err := profiledb.New(ps, 1*time.Minute, "none")
	require.NoError(tb, err)

	return db
}

func TestDefaultProfileDB(t *testing.T) {
	dev := &agd.Device{
		ID:       profiledbtest.DeviceID,
		LinkedIP: testClientIPv4,
		DedicatedIPs: []netip.Addr{
			testDedicatedIPv4,
		},
	}

	devicesCh := make(chan []*agd.Device, 1)
	devicesCh <- []*agd.Device{dev}
	db := newDefaultProfileDB(t, devicesCh)

	t.Run("by_device_id", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		p, d, err := db.ProfileByDeviceID(ctx, profiledbtest.DeviceID)
		require.NoError(t, err)

		assert.Equal(t, profiledbtest.ProfileID, p.ID)
		assert.Equal(t, d, dev)
	})

	t.Run("by_dedicated_ip", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		p, d, err := db.ProfileByDedicatedIP(ctx, testDedicatedIPv4)
		require.NoError(t, err)

		assert.Equal(t, profiledbtest.ProfileID, p.ID)
		assert.Equal(t, d, dev)
	})

	t.Run("by_linked_ip", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		p, d, err := db.ProfileByLinkedIP(ctx, testClientIPv4)
		require.NoError(t, err)

		assert.Equal(t, profiledbtest.ProfileID, p.ID)
		assert.Equal(t, d, dev)
	})
}

func TestDefaultProfileDB_ProfileByDedicatedIP_removedDevice(t *testing.T) {
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

	// The second response, the device is removed.
	devicesCh <- nil

	err = db.Refresh(ctx)
	require.NoError(t, err)

	assert.Eventually(t, func() (ok bool) {
		_, d, err = db.ProfileByDedicatedIP(ctx, testDedicatedIPv4)

		return errors.Is(err, profiledb.ErrDeviceNotFound)
	}, testTimeout, testTimeout/10)
}

func TestDefaultProfileDB_ProfileByDedicatedIP_deviceNewIP(t *testing.T) {
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

func TestDefaultProfileDB_ProfileByLinkedIP_removedDevice(t *testing.T) {
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
	var gotSyncTime time.Time
	onProfiles := func(
		_ context.Context,
		req *profiledb.StorageRequest,
	) (resp *profiledb.StorageResponse, err error) {
		gotSyncTime = req.SyncTime

		return &profiledb.StorageResponse{}, nil
	}

	ps := &agdtest.ProfileStorage{
		OnProfiles: onProfiles,
	}

	// Use the time with monotonic clocks stripped down.
	wantSyncTime := time.Now().Round(0).UTC()

	prof, dev := profiledbtest.NewProfile(t)

	cacheFilePath := filepath.Join(t.TempDir(), "profiles.pb")
	pbCache := filecachepb.New(cacheFilePath)
	err := pbCache.Store(&internal.FileCache{
		SyncTime: wantSyncTime,
		Profiles: []*agd.Profile{prof},
		Devices:  []*agd.Device{dev},
		Version:  internal.FileCacheVersion,
	})
	require.NoError(t, err)

	db, err := profiledb.New(ps, 1*time.Minute, cacheFilePath)
	require.NoError(t, err)
	require.NotNil(t, db)

	assert.Equal(t, wantSyncTime, gotSyncTime)

	p, d, err := db.ProfileByDeviceID(context.Background(), dev.ID)
	require.NoError(t, err)
	assert.Equal(t, dev, d)
	assert.Equal(t, prof, p)
}

func TestDefaultProfileDB_fileCache_badVersion(t *testing.T) {
	storageCalled := false
	ps := &agdtest.ProfileStorage{
		OnProfiles: func(
			_ context.Context,
			_ *profiledb.StorageRequest,
		) (resp *profiledb.StorageResponse, err error) {
			storageCalled = true

			return &profiledb.StorageResponse{}, nil
		},
	}

	cacheFilePath := filepath.Join(t.TempDir(), "profiles.pb")
	pbCache := filecachepb.New(cacheFilePath)
	err := pbCache.Store(&internal.FileCache{
		Version: 10000,
	})
	require.NoError(t, err)

	db, err := profiledb.New(ps, 1*time.Minute, cacheFilePath)
	assert.NoError(t, err)
	assert.NotNil(t, db)
	assert.True(t, storageCalled)
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
		for i := 0; i < b.N; i++ {
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
		for i := 0; i < b.N; i++ {
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
	//	BenchmarkDefaultProfileDB_ProfileByDeviceID/success-16          59396382                21.36 ns/op            0 B/op          0 allocs/op
	//	BenchmarkDefaultProfileDB_ProfileByDeviceID/not_found-16        74497800                16.45 ns/op            0 B/op          0 allocs/op
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
		for i := 0; i < b.N; i++ {
			profSink, devSink, errSink = db.ProfileByLinkedIP(ctx, testClientIPv4)
		}

		assert.NotNil(b, profSink)
		assert.NotNil(b, devSink)
		assert.NoError(b, errSink)
	})

	b.Run("not_found", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
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
	//	BenchmarkDefaultProfileDB_ProfileByLinkedIP/success-16          24822542                44.11 ns/op            0 B/op          0 allocs/op
	//	BenchmarkDefaultProfileDB_ProfileByLinkedIP/not_found-16        63539154                20.04 ns/op            0 B/op          0 allocs/op
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
		for i := 0; i < b.N; i++ {
			profSink, devSink, errSink = db.ProfileByDedicatedIP(ctx, testClientIPv4)
		}

		assert.NotNil(b, profSink)
		assert.NotNil(b, devSink)
		assert.NoError(b, errSink)
	})

	b.Run("not_found", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
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
	//	BenchmarkDefaultProfileDB_ProfileByDedicatedIP/success-16               22697658                48.19 ns/op            0 B/op          0 allocs/op
	//	BenchmarkDefaultProfileDB_ProfileByDedicatedIP/not_found-16             61062061                19.89 ns/op            0 B/op          0 allocs/op
}
