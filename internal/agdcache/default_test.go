package agdcache_test

import (
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/golibs/testutil/faketime"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/bluele/gcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault(t *testing.T) {
	var (
		testTimeNow = time.Now()
		nowLater    = testTimeNow.Add(2 * expDuration)
	)

	clock := &faketime.Clock{
		OnNow: func() (now time.Time) { return testTimeNow },
	}

	cache, err := agdcache.New[string, int](&agdcache.Config{
		Clock: clock,
		Count: 10,
	})
	require.NoError(t, err)

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

	cache.SetWithExpire(key, val, expDuration)
	assert.Equal(t, 1, cache.Len())

	v, ok = cache.Get(key)
	assert.Equal(t, val, v)
	assert.True(t, ok)

	clock.OnNow = func() (now time.Time) { return nowLater }

	v, ok = cache.Get(key)
	assert.Equal(t, 0, v)
	assert.False(t, ok)

	assert.Equal(t, 0, cache.Len())
}

func BenchmarkDefault(b *testing.B) {
	var ok bool

	b.Run("set", func(b *testing.B) {
		cache := newDefault(b)

		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			cache.Set(i, i)
			_, ok = cache.Get(i)
		}

		assert.True(b, ok)
	})

	b.Run("set_expire", func(b *testing.B) {
		cache := newDefault(b)

		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			cache.SetWithExpire(i, i, 2000)
			_, ok = cache.Get(i)
		}

		assert.True(b, ok)
	})

	// Most recent results:
	//
	// goos: darwin
	// goarch: arm64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/agdcache
	// cpu: Apple M1 Pro
	// BenchmarkDefault/set-8         	 7764472	       138.6 ns/op	      56 B/op	       2 allocs/op
	// BenchmarkDefault/set_expire-8  	 4727664	       246.5 ns/op	      56 B/op	       2 allocs/op
}

func FuzzDefault(f *testing.F) {
	const (
		size        = 1_000
		secondsSeed = uint(1)
	)

	f.Add("key", 1, secondsSeed, 1)
	f.Add("key", 1, secondsSeed, 2)
	f.Add("key", 1, secondsSeed, 3)

	now := time.Now()

	f.Fuzz(func(t *testing.T, key string, val int, seconds uint, op int) {
		clock := &faketime.Clock{
			OnNow: func() (n time.Time) {
				return now
			},
		}

		cache, err := agdcache.New[string, int](&agdcache.Config{
			Clock: clock,
			Count: size,
		})
		require.NoError(t, err)

		gCache := gcache.New(size).LRU().Clock(clock).Build()

		switch {
		case op%2 == 0:
			cache.Set(key, val)
			err = gCache.Set(key, val)
			require.NoError(t, err)
		case op%3 == 0:
			dur := time.Duration(seconds) * time.Second

			cache.SetWithExpire(key, val, dur)
			err = gCache.SetWithExpire(key, val, dur)
			require.NoError(t, err)
		case op%5 == 0:
			cache.Clear()
			gCache.Purge()
		}

		clock.OnNow = func() (n time.Time) {
			return now.Add(1 * time.Second)
		}

		got, ok := cache.Get(key)
		gGot, err := gCache.Get(key)
		gVal, gValOk := gGot.(int)
		if !gValOk {
			gVal = 0
		}

		require.Equalf(
			t,
			err == nil,
			ok,
			"key %q, val %d, dur %d, op %d: incorrect ok",
			key, val, seconds, op,
		)
		require.Equalf(
			t,
			gVal,
			got,
			"key %q, val %d, dur %d, op %d: incorrect val",
			key, val, seconds, op,
		)

		l := cache.Len()
		goL := gCache.Len(false)
		require.Equal(t, l, goL)
	})
}

// newDefault returns a new cache for testing.
func newDefault(tb testing.TB) (cache *agdcache.Default[int, int]) {
	cache, err := agdcache.New[int, int](&agdcache.Config{
		Clock: timeutil.SystemClock{},
		Count: 10_000,
	})
	require.NoError(tb, err)

	return cache
}
