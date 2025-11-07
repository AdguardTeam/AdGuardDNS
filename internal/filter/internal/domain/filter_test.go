package domain_test

import (
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/composite"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/domain"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/publicsuffix"
)

// type check
//
// TODO(f.setrakov): Use export via internal test to avoid loop.
var _ composite.RequestFilter = (*domain.Filter)(nil)

// testDomains is the host data for tests.
const testDomains = filtertest.HostCategory + "\n"

func TestFilter_FilterRequest(t *testing.T) {
	t.Parallel()

	msgs := agdtest.NewConstructor(t)

	testCases := []struct {
		name       string
		host       string
		qType      dnsmsg.RRType
		wantResult bool
	}{{
		name:       "host_not_a_or_aaaa",
		host:       filtertest.HostCategory,
		qType:      dns.TypeTXT,
		wantResult: false,
	}, {
		name:       "host_success",
		host:       filtertest.HostCategory,
		qType:      dns.TypeA,
		wantResult: true,
	}, {
		name:       "host_success_subdomain",
		host:       filtertest.HostCategorySub,
		qType:      dns.TypeA,
		wantResult: true,
	}, {
		name:       "host_no_match",
		host:       filtertest.Host,
		qType:      dns.TypeA,
		wantResult: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := filtertest.NewDomainFilter(t, testDomains)

			ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
			req := dnsservertest.NewReq(dns.Fqdn(tc.host), tc.qType, dns.ClassINET)

			r, err := f.FilterRequest(ctx, &filter.Request{
				DNS:      req,
				Messages: msgs,
				Host:     tc.host,
				QType:    tc.qType,
			})
			require.NoError(t, err)

			var wantRes filter.Result
			if tc.wantResult {
				wantRes = newModRespResult(
					t,
					req,
					msgs,
					netip.IPv4Unspecified(),
					filtertest.HostCategory,
				)
			}

			filtertest.AssertEqualResult(t, wantRes, r)
		})
	}
}

func TestFilter_FilterRequest_cache(t *testing.T) {
	t.Parallel()

	f := filtertest.NewDomainFilter(t, testDomains)

	require.True(t, t.Run("cached_success", func(t *testing.T) {
		t.Parallel()

		req := filtertest.NewARequest(t, filtertest.HostCategory)

		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
		original, err := f.FilterRequest(ctx, req)
		require.NoError(t, err)

		cached, err := f.FilterRequest(ctx, req)
		require.NoError(t, err)

		filtertest.AssertEqualResult(t, cached, original)
	}))

	require.True(t, t.Run("cached_no_match", func(t *testing.T) {
		t.Parallel()

		req := filtertest.NewARequest(t, filtertest.Host)

		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
		original, err := f.FilterRequest(ctx, req)
		require.NoError(t, err)

		cached, err := f.FilterRequest(ctx, req)
		require.NoError(t, err)

		filtertest.AssertEqualResult(t, cached, original)
	}))
}

func TestFilter_Refresh(t *testing.T) {
	t.Parallel()

	refrCh := make(chan struct{}, 1)
	cachePath, srvURL := filtertest.PrepareRefreshable(t, refrCh, testDomains, http.StatusOK)

	f, err := domain.NewFilter(&domain.FilterConfig{
		Logger:           slogutil.NewDiscardLogger(),
		Cloner:           agdtest.NewCloner(),
		CacheManager:     agdcache.EmptyManager{},
		URL:              srvURL,
		ErrColl:          agdtest.NewErrorCollector(),
		DomainMetrics:    domain.EmptyMetrics{},
		Metrics:          filter.EmptyMetrics{},
		PublicSuffixList: publicsuffix.List,
		ID:               filtertest.RuleListIDDomain,
		CachePath:        cachePath,
		Staleness:        filtertest.Staleness,
		CacheTTL:         filtertest.CacheTTL,
		CacheCount:       filtertest.CacheCount,
		MaxSize:          filtertest.FilterMaxSize,
		SubDomainNum:     filtertest.SubDomainNum,
	})
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
	require.NoError(t, f.RefreshInitial(ctx))

	testutil.RequireReceive(t, refrCh, filtertest.Timeout)

	ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)
	err = f.Refresh(ctx)
	assert.NoError(t, err)

	assert.Empty(t, refrCh)
}

func TestFilter_FilterRequest_staleCache(t *testing.T) {
	t.Parallel()

	refrCh := make(chan struct{}, 1)
	cachePath, srvURL := filtertest.PrepareRefreshable(t, refrCh, testDomains, http.StatusOK)

	msgs := agdtest.NewConstructor(t)

	// Put some initial data into the cache to avoid the first refresh.

	cf, err := os.OpenFile(cachePath, os.O_WRONLY|os.O_APPEND, os.ModeAppend)
	require.NoError(t, err)

	_, err = cf.WriteString(filtertest.Host + "\n")
	require.NoError(t, err)
	require.NoError(t, cf.Close())

	// Create the filter.

	cloner := agdtest.NewCloner()

	fconf := &domain.FilterConfig{
		Logger:           slogutil.NewDiscardLogger(),
		Cloner:           cloner,
		CacheManager:     agdcache.EmptyManager{},
		URL:              srvURL,
		ErrColl:          agdtest.NewErrorCollector(),
		DomainMetrics:    domain.EmptyMetrics{},
		Metrics:          filter.EmptyMetrics{},
		PublicSuffixList: publicsuffix.List,
		ID:               filtertest.RuleListIDDomain,
		CachePath:        cachePath,
		Staleness:        filtertest.Staleness,
		CacheTTL:         filtertest.CacheTTL,
		CacheCount:       filtertest.CacheCount,
		MaxSize:          filtertest.FilterMaxSize,
		SubDomainNum:     filtertest.SubDomainNum,
	}
	f, err := domain.NewFilter(fconf)
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
	require.NoError(t, f.RefreshInitial(ctx))

	assert.Empty(t, refrCh)

	// Test the following:
	//
	//  1. Check that the stale rules cache is used.
	//  2. Refresh the stale rules cache.
	//  3. Ensure the result cache is cleared.
	//  4. Ensure the stale rules aren't used.

	hostReq := filtertest.NewARequest(t, filtertest.HostCategory)
	otherHostReq := filtertest.NewARequest(t, filtertest.Host)

	require.True(t, t.Run("hit_cached_host", func(t *testing.T) {
		ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)

		var r filter.Result
		r, err = f.FilterRequest(ctx, otherHostReq)
		require.NoError(t, err)

		wantRes := newModRespResult(
			t,
			otherHostReq.DNS,
			msgs,
			netip.IPv4Unspecified(),
			filtertest.Host,
		)
		filtertest.AssertEqualResult(t, wantRes, r)
	}))

	require.True(t, t.Run("refresh", func(t *testing.T) {
		// Make the cache stale.
		now := time.Now()
		err = os.Chtimes(cachePath, now, now.Add(-2*fconf.Staleness))
		require.NoError(t, err)

		ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)

		err = f.Refresh(ctx)
		assert.NoError(t, err)

		testutil.RequireReceive(t, refrCh, filtertest.Timeout)
	}))

	require.True(t, t.Run("previously_cached", func(t *testing.T) {
		ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)

		var r filter.Result
		r, err = f.FilterRequest(ctx, otherHostReq)
		require.NoError(t, err)

		assert.Nil(t, r)
	}))

	require.True(t, t.Run("new_host", func(t *testing.T) {
		ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)

		var r filter.Result
		r, err = f.FilterRequest(ctx, hostReq)
		require.NoError(t, err)

		wantRes := newModRespResult(
			t,
			hostReq.DNS,
			msgs,
			netip.IPv4Unspecified(),
			filtertest.HostCategory,
		)
		filtertest.AssertEqualResult(t, wantRes, r)
	}))
}

// newModRespResult is a helper for creating modified response result for tests.
// req must not be nil.
func newModRespResult(
	tb testing.TB,
	req *dns.Msg,
	messages *dnsmsg.Constructor,
	replIP netip.Addr,
	rule string,
) (r *filter.ResultModifiedResponse) {
	tb.Helper()

	resp, err := messages.NewRespIP(req, replIP)
	require.NoError(tb, err)

	return &filter.ResultModifiedResponse{
		Msg:  resp,
		List: filtertest.RuleListIDDomain,
		Rule: filter.RuleText(rule),
	}
}
