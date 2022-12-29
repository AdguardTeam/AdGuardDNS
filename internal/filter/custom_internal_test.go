package filter

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/bluele/gcache"
)

// errorCollector is an agd.ErrorCollector for tests.  This is a copy of the
// code from package agdtest to evade an import cycle.
type errorCollector struct {
	OnCollect func(ctx context.Context, err error)
}

// type check
var _ agd.ErrorCollector = (*errorCollector)(nil)

// Collect implements the agd.GeoIP interface for *GeoIP.
func (c *errorCollector) Collect(ctx context.Context, err error) {
	c.OnCollect(ctx, err)
}

var ruleListsSink []*ruleListFilter

func BenchmarkCustomFilters_ruleCache(b *testing.B) {
	f := &customFilters{
		cache: gcache.New(1).LRU().Build(),
		errColl: &errorCollector{
			OnCollect: func(ctx context.Context, err error) { panic("not implemented") },
		},
	}

	p := &agd.Profile{
		ID:         testProfID,
		UpdateTime: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		CustomRules: []agd.FilterRuleText{
			"||example.com",
			"||example.org",
			"||example.net",
		},
	}

	ctx := context.Background()

	b.Run("cache", func(b *testing.B) {
		rls := make([]*ruleListFilter, 0, 1)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ruleListsSink = f.appendRuleLists(ctx, rls, p)
		}
	})

	b.Run("no_cache", func(b *testing.B) {
		rls := make([]*ruleListFilter, 0, 1)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Update the time on each iteration to make sure that the cache is
			// never used.
			p.UpdateTime.Add(1 * time.Millisecond)
			ruleListsSink = f.appendRuleLists(ctx, rls, p)
		}
	})
}
