package agdcache_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/stretchr/testify/assert"
)

func TestLRU(t *testing.T) {
	cache := agdcache.NewLRU[string, int](&agdcache.LRUConfig{
		Count: 10,
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

func BenchmarkLRU(b *testing.B) {
	cache := agdcache.NewLRU[int, int](&agdcache.LRUConfig{
		Count: 10_000,
	})

	var ok bool

	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		cache.Set(i, i)
		_, ok = cache.Get(i)
	}

	assert.True(b, ok)

	// Most recent results:
	//
	// goos: darwin
	// goarch: arm64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/agdcache
	// cpu: Apple M1 Pro
	// BenchmarkLRU-8   	 5104281	       207.2 ns/op	     136 B/op	       5 allocs/op
}

func BenchmarkLRU_expire(b *testing.B) {
	cache := agdcache.NewLRU[int, int](&agdcache.LRUConfig{
		Count: 10_000,
	})

	var ok bool

	b.Run("default_expire", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			cache.Set(i, i)
			_, ok = cache.Get(i)
		}

		assert.True(b, ok)

		// Most recent results:
		//
		// goos: darwin
		// goarch: arm64
		// pkg: github.com/AdguardTeam/AdGuardDNS/internal/agdcache
		// cpu: Apple M1 Pro
		// BenchmarkLRU_expire/default_expire-8         	 4883622	       208.6 ns/op	     136 B/op	       5 allocs/op
	})

	b.Run("set_expire", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			cache.SetWithExpire(i, i, 2000)
			_, ok = cache.Get(i)
		}

		assert.True(b, ok)

		// Most recent results:
		//
		// goos: darwin
		// goarch: arm64
		// pkg: github.com/AdguardTeam/AdGuardDNS/internal/agdcache
		// cpu: Apple M1 Pro
		// BenchmarkLRU_expire/set_expire-8             	 3620727	       328.7 ns/op	     160 B/op	       5 allocs/op
	})
}
