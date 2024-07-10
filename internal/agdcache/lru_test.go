package agdcache_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/stretchr/testify/assert"
)

func TestLRU(t *testing.T) {
	const (
		key = "key"
		val = 123

		nonExistingKey = "nonExistingKey"
	)

	cache := agdcache.NewLRU[string, int](&agdcache.LRUConfig{
		Size: 10,
	})

	cache.Set(key, val)

	assert.Equal(t, 1, cache.Len())

	v, ok := cache.Get(key)
	assert.Equal(t, val, v)
	assert.True(t, ok)

	v, ok = cache.Get(nonExistingKey)
	assert.Equal(t, 0, v)
	assert.False(t, ok)

	cache.Clear()

	assert.Equal(t, 0, cache.Len())
}
