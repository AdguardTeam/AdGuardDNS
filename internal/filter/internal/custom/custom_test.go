package custom_test

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/custom"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testProfID is the profile ID for tests.
const testProfID agd.ProfileID = "prof1234"

func TestFilters_Get(t *testing.T) {
	f := custom.New(&custom.Config{
		Logger:  slogutil.NewDiscardLogger(),
		ErrColl: agdtest.NewErrorCollector(),
		CacheConf: &agdcache.LRUConfig{
			Size: 1,
		},
		CacheManager: agdcache.EmptyManager{},
	})

	p := &agd.Profile{
		ID:         testProfID,
		UpdateTime: time.Now(),
		CustomRules: []agd.FilterRuleText{
			"||first.example",
		},
	}

	ctx := context.Background()

	rl := f.Get(ctx, p)
	require.NotNil(t, rl)

	// Recheck cached.
	cachedRL := f.Get(ctx, p)
	require.NotNil(t, cachedRL)

	assert.Same(t, rl, cachedRL)
}

var ruleListSink *rulelist.Immutable

func BenchmarkFilters_Get(b *testing.B) {
	f := custom.New(&custom.Config{
		Logger:  slogutil.NewDiscardLogger(),
		ErrColl: agdtest.NewErrorCollector(),
		CacheConf: &agdcache.LRUConfig{
			Size: 1,
		},
		CacheManager: agdcache.EmptyManager{},
	})

	p := &agd.Profile{
		ID:         testProfID,
		UpdateTime: time.Now(),
		CustomRules: []agd.FilterRuleText{
			"||first.example",
			"||second.example",
			"||third.example",
		},
	}

	ctx := context.Background()

	b.Run("cache", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			ruleListSink = f.Get(ctx, p)
		}
	})

	b.Run("no_cache", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			// Update the time on each iteration to make sure that the cache is
			// never used.
			p.UpdateTime = p.UpdateTime.Add(1 * time.Millisecond)
			ruleListSink = f.Get(ctx, p)
		}
	})

	// Most recent result, on a ThinkPad X13 with a Ryzen Pro 7 CPU:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/custom
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkFilters_Get/cache-16            7870251               233.4 ns/op            16 B/op          1 allocs/op
	//	BenchmarkFilters_Get/no_cache-16           53073             23490 ns/op           14610 B/op         93 allocs/op
}
