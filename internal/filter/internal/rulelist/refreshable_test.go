package rulelist_test

import (
	"net/http"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshable_RulesCount(t *testing.T) {
	rl := rulelist.NewFromString(
		filtertest.RuleBlockStr,
		filtertest.RuleListID1,
		"",
		rulelist.EmptyResultCache{},
	)

	assert.Equal(t, 1, rl.RulesCount())
}

func TestRefreshable_SetURLFilterResult_cache(t *testing.T) {
	cache := rulelist.NewResultCache(filtertest.CacheCount, true)
	rl := rulelist.NewFromString(filtertest.RuleBlockStr, filtertest.RuleListID1, "", cache)

	require.True(t, t.Run("blocked", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
		req := &urlfilter.DNSRequest{
			ClientIP: filtertest.IPv4Client,
			Hostname: filtertest.HostBlocked,
			DNSType:  dns.TypeA,
		}
		res := &urlfilter.DNSResult{}

		ok := rl.SetURLFilterResult(ctx, req, res)
		require.True(t, ok)

		assert.Len(t, res.NetworkRules, 1)
		r := res.NetworkRules[0]

		res.Reset()
		ok = rl.SetURLFilterResult(ctx, req, res)
		require.True(t, ok)

		assert.Same(t, r, res.NetworkRules[0])
	}))

	require.True(t, t.Run("none", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
		req := &urlfilter.DNSRequest{
			ClientIP: filtertest.IPv4Client,
			Hostname: filtertest.Host,
			DNSType:  dns.TypeA,
		}
		res := &urlfilter.DNSResult{}

		ok := rl.SetURLFilterResult(ctx, req, res)
		assert.False(t, ok)

		res.Reset()
		ok = rl.SetURLFilterResult(ctx, req, res)
		assert.False(t, ok)
	}))
}

func TestRefreshable_ID(t *testing.T) {
	rl := rulelist.NewFromString(
		filtertest.RuleBlockStr,
		filtertest.RuleListID1,
		filtertest.BlockedServiceID1Str,
		rulelist.EmptyResultCache{},
	)

	gotID, gotSvcID := rl.ID()
	assert.Equal(t, filtertest.RuleListID1, gotID)
	assert.Equal(t, filtertest.BlockedServiceID1, gotSvcID)
}

func TestRefreshable_Refresh(t *testing.T) {
	cachePath, srvURL := filtertest.PrepareRefreshable(
		t,
		nil,
		filtertest.RuleBlockStr,
		http.StatusOK,
	)
	rl, err := rulelist.NewRefreshable(
		&refreshable.Config{
			Logger:    slogutil.NewDiscardLogger(),
			URL:       srvURL,
			ID:        filtertest.RuleListID1,
			CachePath: cachePath,
			Staleness: filtertest.Staleness,
			MaxSize:   filtertest.FilterMaxSize,
		},
		rulelist.NewResultCache(filtertest.CacheCount, true),
	)
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
	err = rl.Refresh(ctx, false)
	require.NoError(t, err)

	assert.Equal(t, 1, rl.RulesCount())

	ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
	req := &urlfilter.DNSRequest{
		ClientIP: filtertest.IPv4Client,
		Hostname: filtertest.HostBlocked,
		DNSType:  dns.TypeA,
	}
	res := &urlfilter.DNSResult{}

	ok := rl.SetURLFilterResult(ctx, req, res)
	require.True(t, ok)

	assert.Len(t, res.NetworkRules, 1)
}

func BenchmarkRefreshable_SetURLFilterResult(b *testing.B) {
	ctx := b.Context()

	benchCases := []struct {
		request *urlfilter.DNSRequest
		cache   rulelist.ResultCache
		want    require.BoolAssertionFunc
		name    string
	}{{
		name:  "blocked",
		cache: rulelist.EmptyResultCache{},
		request: &urlfilter.DNSRequest{
			ClientIP: filtertest.IPv4Client,
			Hostname: filtertest.HostBlocked,
			DNSType:  dns.TypeA,
		},
		want: require.True,
	}, {
		name:  "other",
		cache: rulelist.EmptyResultCache{},
		request: &urlfilter.DNSRequest{
			ClientIP: filtertest.IPv4Client,
			Hostname: filtertest.Host,
			DNSType:  dns.TypeA,
		},
		want: require.False,
	}, {
		name:  "blocked_with_cache",
		cache: rulelist.NewResultCache(filtertest.CacheCount, true),
		request: &urlfilter.DNSRequest{
			ClientIP: filtertest.IPv4Client,
			Hostname: filtertest.HostBlocked,
			DNSType:  dns.TypeA,
		},
		want: require.True,
	}, {
		name:  "other_with_cache",
		cache: rulelist.NewResultCache(filtertest.CacheCount, true),
		request: &urlfilter.DNSRequest{
			ClientIP: filtertest.IPv4Client,
			Hostname: filtertest.Host,
			DNSType:  dns.TypeA,
		},
		want: require.False,
	}}

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			rl := rulelist.NewFromString(
				filtertest.RuleBlockStr,
				filtertest.RuleListID1,
				"",
				bc.cache,
			)

			res := &urlfilter.DNSResult{}

			// Warmup to fill the slices.
			ok := rl.SetURLFilterResult(ctx, bc.request, res)
			bc.want(b, ok)

			b.ReportAllocs()
			for b.Loop() {
				res.Reset()
				ok = rl.SetURLFilterResult(ctx, bc.request, res)
			}

			bc.want(b, ok)
		})
	}

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist
	//	cpu: Apple M3
	//	BenchmarkRefreshable_SetURLFilterResult/blocked-8         	             2762634	        428.2 ns/op	      24 B/op	       1 allocs/op
	//	BenchmarkRefreshable_SetURLFilterResult/other-8           	             5687978	        242.0 ns/op	      24 B/op	       1 allocs/op
	//	BenchmarkRefreshable_SetURLFilterResult/blocked_with_cache-8         	33770551	        35.38 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkRefreshable_SetURLFilterResult/other_with_cache-8           	43484037	        31.63 ns/op	       0 B/op	       0 allocs/op
}
