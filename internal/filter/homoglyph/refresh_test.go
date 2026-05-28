package homoglyph_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter/homoglyph"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/require"
)

func TestFilter_Refresh(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "homoglyph.json")
	f := newTestFilter(t, &homoglyph.Config{
		Storage:   newTestStorage(testIndexExc),
		CachePath: cachePath,
	})

	require.True(t, t.Run("with_present_cache", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
		err := f.Refresh(ctx)
		require.NoError(t, err)
	}))

	require.True(t, t.Run("with_cache_removed", func(t *testing.T) {
		err := os.Remove(cachePath)
		require.NoError(t, err)

		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
		err = f.RefreshInitial(ctx)
		require.NoError(t, err)
	}))
}
