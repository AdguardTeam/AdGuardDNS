package filecachepb_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/filecachepb"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/profiledbtest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorage(t *testing.T) {
	prof, dev := profiledbtest.NewProfile(t)
	cachePath := filepath.Join(t.TempDir(), "profiles.pb")
	s := filecachepb.New(&filecachepb.Config{
		Logger:               testLogger,
		BaseCustomLogger:     testLogger,
		CacheFilePath:        cachePath,
		ResponseSizeEstimate: profiledbtest.RespSzEst,
	})
	require.NotNil(t, s)

	fc := &internal.FileCache{
		SyncTime: time.Now().Round(0).UTC(),
		Profiles: []*agd.Profile{prof},
		Devices:  []*agd.Device{dev},
		Version:  internal.FileCacheVersion,
	}

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	err := s.Store(ctx, fc)
	require.NoError(t, err)

	gotFC, err := s.Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, gotFC)
	require.NotEmpty(t, *gotFC)

	assert.Equal(t, fc, gotFC)
}

func TestStorage_Load_noFile(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "profiles.pb")
	s := filecachepb.New(&filecachepb.Config{
		Logger:               testLogger,
		BaseCustomLogger:     testLogger,
		CacheFilePath:        cachePath,
		ResponseSizeEstimate: profiledbtest.RespSzEst,
	})
	require.NotNil(t, s)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	fc, err := s.Load(ctx)
	assert.NoError(t, err)
	assert.Nil(t, fc)
}
