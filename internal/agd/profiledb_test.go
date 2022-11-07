package agd_test

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newDefaultProfileDB returns a new default profile database for tests.
func newDefaultProfileDB(tb testing.TB, dev *agd.Device) (db *agd.DefaultProfileDB) {
	tb.Helper()

	onProfiles := func(
		_ context.Context,
		_ *agd.PSProfilesRequest,
	) (resp *agd.PSProfilesResponse, err error) {
		return &agd.PSProfilesResponse{
			Profiles: []*agd.Profile{{
				ID:      testProfID,
				Devices: []*agd.Device{dev},
			}},
		}, nil
	}

	ds := &agdtest.ProfileStorage{
		OnProfiles: onProfiles,
	}

	cacheFilePath := filepath.Join(tb.TempDir(), "profiles.json")
	db, err := agd.NewDefaultProfileDB(ds, 1*time.Minute, cacheFilePath)
	require.NoError(tb, err)

	return db
}

func TestDefaultProfileDB(t *testing.T) {
	dev := &agd.Device{
		ID:       testDevID,
		LinkedIP: &testClientIPv4,
	}

	db := newDefaultProfileDB(t, dev)

	t.Run("by_device_id", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		p, d, err := db.ProfileByDeviceID(ctx, testDevID)
		require.NoError(t, err)

		assert.Equal(t, testProfID, p.ID)
		assert.Equal(t, d, dev)
	})

	t.Run("by_ip", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		p, d, err := db.ProfileByIP(ctx, testClientIPv4)
		require.NoError(t, err)

		assert.Equal(t, testProfID, p.ID)
		assert.Equal(t, d, dev)
	})
}

var profSink *agd.Profile

var devSink *agd.Device

var errSink error

func BenchmarkDefaultProfileDB_ProfileByDeviceID(b *testing.B) {
	dev := &agd.Device{
		ID: testDevID,
	}

	db := newDefaultProfileDB(b, dev)
	ctx := context.Background()

	b.Run("success", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			profSink, devSink, errSink = db.ProfileByDeviceID(ctx, testDevID)
		}

		assert.NotNil(b, profSink)
		assert.NotNil(b, devSink)
		assert.NoError(b, errSink)
	})

	const wrongDevID = testDevID + "_bad"

	b.Run("not_found", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			profSink, devSink, errSink = db.ProfileByDeviceID(ctx, wrongDevID)
		}

		assert.Nil(b, profSink)
		assert.Nil(b, devSink)
		assert.ErrorAs(b, errSink, new(agd.NotFoundError))
	})
}

func BenchmarkDefaultProfileDB_ProfileByIP(b *testing.B) {
	dev := &agd.Device{
		ID:       testDevID,
		LinkedIP: &testClientIPv4,
	}

	db := newDefaultProfileDB(b, dev)
	ctx := context.Background()

	b.Run("success", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			profSink, devSink, errSink = db.ProfileByIP(ctx, testClientIPv4)
		}

		assert.NotNil(b, profSink)
		assert.NotNil(b, devSink)
		assert.NoError(b, errSink)
	})

	wrongClientIP := netip.MustParseAddr("5.6.7.8")

	b.Run("not_found", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			profSink, devSink, errSink = db.ProfileByIP(ctx, wrongClientIP)
		}

		assert.Nil(b, profSink)
		assert.Nil(b, devSink)
		assert.ErrorAs(b, errSink, new(agd.NotFoundError))
	})
}
