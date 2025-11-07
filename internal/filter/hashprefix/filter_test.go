package hashprefix_test

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
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/composite"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/publicsuffix"
)

// type check
var _ composite.RequestFilter = (*hashprefix.Filter)(nil)

func TestFilter_FilterRequest(t *testing.T) {
	t.Parallel()

	msgs := agdtest.NewConstructor(t)

	testCases := []struct {
		name       string
		host       string
		replHost   string
		wantRule   filter.RuleText
		qType      dnsmsg.RRType
		wantResult bool
	}{{
		name:       "host_not_a_or_aaaa",
		host:       filtertest.HostAdultContent,
		replHost:   filtertest.HostAdultContentRepl,
		wantRule:   "",
		qType:      dns.TypeTXT,
		wantResult: false,
	}, {
		name:       "host_success",
		host:       filtertest.HostAdultContent,
		replHost:   filtertest.HostAdultContentRepl,
		wantRule:   filtertest.HostAdultContent,
		qType:      dns.TypeA,
		wantResult: true,
	}, {
		name:       "host_success_subdomain",
		host:       filtertest.HostAdultContentSub,
		replHost:   filtertest.HostAdultContentRepl,
		wantRule:   filtertest.HostAdultContent,
		qType:      dns.TypeA,
		wantResult: true,
	}, {
		name:       "host_no_match",
		host:       filtertest.Host,
		replHost:   filtertest.HostAdultContentRepl,
		wantRule:   "",
		qType:      dns.TypeA,
		wantResult: false,
	}, {
		name:       "ip_not_a_or_aaaa",
		host:       filtertest.HostAdultContent,
		replHost:   filtertest.IPv4AdultContentReplStr,
		wantRule:   "",
		qType:      dns.TypeTXT,
		wantResult: false,
	}, {
		name:       "ip_success",
		host:       filtertest.HostAdultContent,
		replHost:   filtertest.IPv4AdultContentReplStr,
		wantRule:   filtertest.HostAdultContent,
		qType:      dns.TypeA,
		wantResult: true,
	}, {
		name:       "ip_success_subdomain",
		host:       filtertest.HostAdultContentSub,
		replHost:   filtertest.IPv4AdultContentReplStr,
		wantRule:   filtertest.HostAdultContent,
		qType:      dns.TypeA,
		wantResult: true,
	}, {
		name:       "ip_no_match",
		replHost:   filtertest.IPv4AdultContentReplStr,
		host:       filtertest.Host,
		wantRule:   "",
		qType:      dns.TypeA,
		wantResult: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := filtertest.NewHashprefixFilterWithRepl(t, filter.IDAdultBlocking, tc.replHost)

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
				if tc.replHost == filtertest.HostAdultContentRepl {
					wantRes = newModReqResult(t, req, tc.wantRule)
				} else {
					wantRes = newModRespResult(t, req, msgs, filtertest.IPv4AdultContentRepl)
				}
			}

			filtertest.AssertEqualResult(t, wantRes, r)
		})
	}
}

func TestFilter_FilterRequest_cache(t *testing.T) {
	t.Parallel()

	f := filtertest.NewHashprefixFilter(t, filter.IDAdultBlocking)

	require.True(t, t.Run("cached_success", func(t *testing.T) {
		t.Parallel()

		req := filtertest.NewARequest(t, filtertest.HostAdultContent)

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

func TestFilter_FilterRequest_https(t *testing.T) {
	t.Parallel()

	require.True(t, t.Run("https", func(t *testing.T) {
		t.Parallel()

		f := filtertest.NewHashprefixFilter(t, filter.IDAdultBlocking)

		req := filtertest.NewRequest(
			t,
			"",
			filtertest.HostAdultContent,
			filtertest.IPv4Client,
			dns.TypeHTTPS,
		)

		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
		r, err := f.FilterRequest(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, r)

		wantRes := newModReqResult(t, req.DNS, filtertest.HostAdultContent)
		filtertest.AssertEqualResult(t, wantRes, r)
	}))

	require.True(t, t.Run("https_ip", func(t *testing.T) {
		t.Parallel()

		f := filtertest.NewHashprefixFilterWithRepl(
			t,
			filter.IDAdultBlocking,
			filtertest.IPv4AdultContentReplStr,
		)

		req := filtertest.NewRequest(
			t,
			"",
			filtertest.HostAdultContent,
			filtertest.IPv4Client,
			dns.TypeHTTPS,
		)

		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
		r, err := f.FilterRequest(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, r)

		m := testutil.RequireTypeAssert[*filter.ResultModifiedResponse](t, r)
		require.NotNil(t, m.Msg)
		require.Len(t, m.Msg.Question, 1)

		assert.Equal(t, m.Msg.Question[0].Qtype, dns.TypeHTTPS)
		assert.Empty(t, m.Msg.Answer)
	}))
}

func TestFilter_Refresh(t *testing.T) {
	t.Parallel()

	refrCh := make(chan struct{}, 1)
	cachePath, srvURL := filtertest.PrepareRefreshable(t, refrCh, testHashes, http.StatusOK)

	strg, err := hashprefix.NewStorage(nil)
	require.NoError(t, err)

	f, err := hashprefix.NewFilter(&hashprefix.FilterConfig{
		Logger:            slogutil.NewDiscardLogger(),
		Cloner:            agdtest.NewCloner(),
		CacheManager:      agdcache.EmptyManager{},
		Hashes:            strg,
		URL:               srvURL,
		ErrColl:           agdtest.NewErrorCollector(),
		HashPrefixMetrics: hashprefix.EmptyMetrics{},
		Metrics:           filter.EmptyMetrics{},
		PublicSuffixList:  publicsuffix.List,
		ID:                filter.IDAdultBlocking,
		CachePath:         cachePath,
		ReplacementHost:   filtertest.HostAdultContentRepl,
		Staleness:         filtertest.Staleness,
		CacheTTL:          filtertest.CacheTTL,
		CacheCount:        filtertest.CacheCount,
		MaxSize:           filtertest.FilterMaxSize,
		SubDomainNum:      filtertest.SubDomainNum,
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
	cachePath, srvURL := filtertest.PrepareRefreshable(t, refrCh, testHashes, http.StatusOK)

	// Put some initial data into the cache to avoid the first refresh.

	cf, err := os.OpenFile(cachePath, os.O_WRONLY|os.O_APPEND, os.ModeAppend)
	require.NoError(t, err)

	_, err = cf.WriteString(filtertest.Host + "\n")
	require.NoError(t, err)
	require.NoError(t, cf.Close())

	// Create the filter.

	strg, err := hashprefix.NewStorage(nil)
	require.NoError(t, err)

	cloner := agdtest.NewCloner()

	fconf := &hashprefix.FilterConfig{
		Logger:            slogutil.NewDiscardLogger(),
		Cloner:            cloner,
		CacheManager:      agdcache.EmptyManager{},
		Hashes:            strg,
		URL:               srvURL,
		ErrColl:           agdtest.NewErrorCollector(),
		HashPrefixMetrics: hashprefix.EmptyMetrics{},
		Metrics:           filter.EmptyMetrics{},
		PublicSuffixList:  publicsuffix.List,
		ID:                filter.IDAdultBlocking,
		CachePath:         cachePath,
		ReplacementHost:   filtertest.HostAdultContentRepl,
		Staleness:         filtertest.Staleness,
		CacheTTL:          filtertest.CacheTTL,
		CacheCount:        filtertest.CacheCount,
		MaxSize:           filtertest.FilterMaxSize,
		SubDomainNum:      filtertest.SubDomainNum,
	}
	f, err := hashprefix.NewFilter(fconf)
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

	hostReq := filtertest.NewARequest(t, filtertest.HostAdultContent)
	otherHostReq := filtertest.NewARequest(t, filtertest.Host)

	require.True(t, t.Run("hit_cached_host", func(t *testing.T) {
		ctx = testutil.ContextWithTimeout(t, filtertest.Timeout)

		var r filter.Result
		r, err = f.FilterRequest(ctx, otherHostReq)
		require.NoError(t, err)

		wantRes := newModReqResult(t, otherHostReq.DNS, filtertest.Host)
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

		wantRes := newModReqResult(t, hostReq.DNS, filtertest.HostAdultContent)
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
) (r *filter.ResultModifiedResponse) {
	tb.Helper()

	resp, err := messages.NewRespIP(req, replIP)
	require.NoError(tb, err)

	return &filter.ResultModifiedResponse{
		Msg:  resp,
		List: filter.IDAdultBlocking,
		Rule: filtertest.HostAdultContent,
	}
}

// newModReqResult is a helper for creating modified request result for tests.
// req must not be nil.
func newModReqResult(
	tb testing.TB,
	req *dns.Msg,
	rule filter.RuleText,
) (r *filter.ResultModifiedRequest) {
	tb.Helper()

	req = dnsmsg.Clone(req)
	req.Question[0].Name = filtertest.FQDNAdultContentRepl

	return &filter.ResultModifiedRequest{
		Msg:  req,
		List: filter.IDAdultBlocking,
		Rule: rule,
	}
}
