package custom_test

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/custom"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testClientConfID is the client configuration ID for tests.
const testClientConfID = "cli1234"

func TestFilters_Get(t *testing.T) {
	f := custom.New(&custom.Config{
		Logger:  slogutil.NewDiscardLogger(),
		ErrColl: agdtest.NewErrorCollector(),
		CacheConf: &agdcache.LRUConfig{
			Count: 1,
		},
		CacheManager: agdcache.EmptyManager{},
	})

	c := &custom.ClientConfig{
		ID:         testClientConfID,
		UpdateTime: time.Now(),
		Rules: []internal.RuleText{
			"||first.example",
		},
		Enabled: true,
	}

	ctx := context.Background()

	rl := f.Get(ctx, c)
	require.NotNil(t, rl)

	// Recheck cached.
	cachedRL := f.Get(ctx, c)
	require.NotNil(t, cachedRL)

	assert.Same(t, rl, cachedRL)
}

var ruleListSink *rulelist.Immutable

func BenchmarkFilters_Get(b *testing.B) {
	f := custom.New(&custom.Config{
		Logger:  slogutil.NewDiscardLogger(),
		ErrColl: agdtest.NewErrorCollector(),
		CacheConf: &agdcache.LRUConfig{
			Count: 1,
		},
		CacheManager: agdcache.EmptyManager{},
	})

	c := &custom.ClientConfig{
		ID:         testClientConfID,
		UpdateTime: time.Now(),
		Rules: []internal.RuleText{
			"||first.example",
			"||second.example",
			"||third.example",
		},
		Enabled: true,
	}

	ctx := context.Background()

	b.Run("cache", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			ruleListSink = f.Get(ctx, c)
		}
	})

	b.Run("no_cache", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			// Update the time on each iteration to make sure that the cache is
			// never used.
			c.UpdateTime = c.UpdateTime.Add(1 * time.Millisecond)
			ruleListSink = f.Get(ctx, c)
		}
	})

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/custom
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkFilters_Get/cache-16         	 5702966	       186.7 ns/op	      16 B/op	       1 allocs/op
	//	BenchmarkFilters_Get/no_cache-16      	   61044	     18373 ns/op	   14488 B/op	      89 allocs/op
}
