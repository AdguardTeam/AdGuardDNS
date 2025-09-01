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
	rl := rulelist.NewFromString(
		filtertest.RuleBlockStr,
		filtertest.RuleListID1,
		"",
		rulelist.EmptyResultCache{},
	)

	ctx := testutil.ContextWithTimeout(b, filtertest.Timeout)
	res := &urlfilter.DNSResult{}

	b.Run("blocked", func(b *testing.B) {
		req := &urlfilter.DNSRequest{
			ClientIP: filtertest.IPv4Client,
			Hostname: filtertest.HostBlocked,
			DNSType:  dns.TypeA,
		}

		var ok bool
		b.ReportAllocs()
		for b.Loop() {
			res.Reset()
			ok = rl.SetURLFilterResult(ctx, req, res)
		}

		require.True(b, ok)
	})

	b.Run("other", func(b *testing.B) {
		req := &urlfilter.DNSRequest{
			ClientIP: filtertest.IPv4Client,
			Hostname: filtertest.Host,
			DNSType:  dns.TypeA,
		}

		var ok bool
		b.ReportAllocs()
		for b.Loop() {
			res.Reset()
			ok = rl.SetURLFilterResult(ctx, req, res)
		}

		require.False(b, ok)
	})

	// Most recent results:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkRefreshable_SetURLFilterResult/blocked-16         	 1340384	       918.6 ns/op	      24 B/op	       1 allocs/op
	//	BenchmarkRefreshable_SetURLFilterResult/other-16           	 2127038	       589.3 ns/op	      24 B/op	       1 allocs/op
}
