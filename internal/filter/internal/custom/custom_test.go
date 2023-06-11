package custom_test

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/custom"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/bluele/gcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// testProfID is the profile ID for tests.
const testProfID agd.ProfileID = "prof1234"

func TestFilters_Get(t *testing.T) {
	f := custom.New(
		gcache.New(1).LRU().Build(),
		&agdtest.ErrorCollector{
			OnCollect: func(ctx context.Context, err error) { panic("not implemented") },
		},
	)

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
	f := custom.New(
		gcache.New(1).LRU().Build(),
		&agdtest.ErrorCollector{
			OnCollect: func(ctx context.Context, err error) { panic("not implemented") },
		},
	)

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
		for i := 0; i < b.N; i++ {
			ruleListSink = f.Get(ctx, p)
		}
	})

	b.Run("no_cache", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
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
