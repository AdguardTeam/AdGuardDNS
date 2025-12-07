package filecacheopb_test

import (
	"cmp"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/filecacheopb"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/profiledbtest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStorage returns new Storage and fills its config with given values.  If
// conf is nil, default config will be used.
func newTestStorage(tb testing.TB, conf *filecacheopb.Config) (storage *filecacheopb.Storage) {
	tb.Helper()

	conf = cmp.Or(conf, &filecacheopb.Config{})

	storage = filecacheopb.New(&filecacheopb.Config{
		Logger:           cmp.Or(conf.Logger, profiledbtest.Logger),
		BaseCustomLogger: cmp.Or(conf.BaseCustomLogger, profiledbtest.Logger),
		ProfileAccessConstructor: cmp.Or(
			conf.ProfileAccessConstructor,
			profiledbtest.ProfileAccessConstructor,
		),
		CacheFilePath: cmp.Or(
			conf.CacheFilePath,
			filepath.Join(tb.TempDir(), "profiles.pb"),
		),
		ResponseSizeEstimate: cmp.Or(conf.ResponseSizeEstimate, profiledbtest.RespSzEst),
	})
	require.NotNil(tb, storage)

	return storage
}

func TestStorage(t *testing.T) {
	prof, dev := profiledbtest.NewProfile(t)
	s := newTestStorage(t, nil)

	fc := &internal.FileCache{
		SyncTime: time.Now().Round(0).UTC(),
		Profiles: []*agd.Profile{prof},
		Devices:  []*agd.Device{dev},
		Version:  internal.FileCacheVersion,
	}

	ctx := profiledbtest.ContextWithTimeout(t)
	n, err := s.Store(ctx, fc)
	require.NoError(t, err)
	assert.Positive(t, n)

	gotFC, err := s.Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, gotFC)
	require.NotEmpty(t, *gotFC)

	agdtest.AssertEqualProfile(t, fc, gotFC)
}

func TestStorage_Load_noFile(t *testing.T) {
	s := newTestStorage(t, nil)

	ctx := profiledbtest.ContextWithTimeout(t)
	fc, err := s.Load(ctx)
	assert.NoError(t, err)
	assert.Nil(t, fc)
}

func TestStorage_Load_BadVersion(t *testing.T) {
	s := newTestStorage(t, nil)
	ctx := profiledbtest.ContextWithTimeout(t)
	fc := &internal.FileCache{
		Version: 1,
	}

	n, err := s.Store(ctx, fc)
	require.NoError(t, err)
	assert.Positive(t, n)

	fc, err = s.Load(ctx)
	assert.Nil(t, fc)

	testutil.AssertErrorMsg(t,
		fmt.Sprintf(
			"%v: version 1 is different from %d",
			internal.CacheVersionError,
			internal.FileCacheVersion,
		),
		err,
	)
}

func BenchmarkStorage(b *testing.B) {
	prof, dev := profiledbtest.NewProfile(b)
	s := newTestStorage(b, nil)

	fc := &internal.FileCache{
		SyncTime: time.Now().Round(0).UTC(),
		Profiles: []*agd.Profile{prof},
		Devices:  []*agd.Device{dev},
		Version:  internal.FileCacheVersion,
	}

	b.Run("store", func(b *testing.B) {
		ctx := profiledbtest.ContextWithTimeout(b)
		b.ReportAllocs()

		for b.Loop() {
			_, err := s.Store(ctx, fc)
			require.NoError(b, err)
		}
	})

	b.Run("load", func(b *testing.B) {
		ctx := profiledbtest.ContextWithTimeout(b)
		b.ReportAllocs()

		for b.Loop() {
			_, err := s.Load(ctx)
			require.NoError(b, err)
		}
	})

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/filecacheopb
	//	cpu: Apple M3
	//	BenchmarkStorage/load-8          	   34159	     35072 ns/op	   14280 B/op	     164 allocs/op
	//	BenchmarkStorage/store-8         	     214	   5437664 ns/op	    6883 B/op	     107 allocs/op
}
