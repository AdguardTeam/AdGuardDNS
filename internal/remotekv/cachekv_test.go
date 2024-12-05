package remotekv_test

import (
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is the common timeout for tests and contexts.
const testTimeout = 1 * time.Second

func TestNewCache(t *testing.T) {
	const testKey = "key"

	testVal := []byte{1, 2, 3}

	cache := remotekv.NewCache(&remotekv.CacheConfig{
		Cache: agdcache.NewLRU[string, []byte](&agdcache.LRUConfig{
			Count: 1,
		}),
	})

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	err := cache.Set(ctx, testKey, testVal)
	require.NoError(t, err)

	got, ok, err := cache.Get(ctx, testKey)
	require.NoError(t, err)
	require.True(t, ok)

	assert.Equal(t, got, testVal)
}
