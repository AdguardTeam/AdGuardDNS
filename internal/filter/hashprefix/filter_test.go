package hashprefix_test

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilter_FilterRequest_host(t *testing.T) {
	testCases := []struct {
		name       string
		host       string
		replHost   string
		wantRule   agd.FilterRuleText
		qType      dnsmsg.RRType
		wantResult bool
	}{{
		name:       "host_not_a_or_aaaa",
		host:       testHost,
		replHost:   testReplHost,
		wantRule:   "",
		qType:      dns.TypeTXT,
		wantResult: false,
	}, {
		name:       "host_success",
		host:       testHost,
		replHost:   testReplHost,
		wantRule:   testHost,
		qType:      dns.TypeA,
		wantResult: true,
	}, {
		name:       "host_success_subdomain",
		host:       "a.b.c." + testHost,
		replHost:   testReplHost,
		wantRule:   testHost,
		qType:      dns.TypeA,
		wantResult: true,
	}, {
		name:       "host_no_match",
		host:       testOtherHost,
		replHost:   testReplHost,
		wantRule:   "",
		qType:      dns.TypeA,
		wantResult: false,
	}, {
		name:       "ip_not_a_or_aaaa",
		host:       testHost,
		replHost:   filtertest.SafeBrowsingReplIPv4Str,
		wantRule:   "",
		qType:      dns.TypeTXT,
		wantResult: false,
	}, {
		name:       "ip_success",
		host:       testHost,
		replHost:   filtertest.SafeBrowsingReplIPv4Str,
		wantRule:   testHost,
		qType:      dns.TypeA,
		wantResult: true,
	}, {
		name:       "ip_success_subdomain",
		host:       "a.b.c." + testHost,
		replHost:   filtertest.SafeBrowsingReplIPv4Str,
		wantRule:   testHost,
		qType:      dns.TypeA,
		wantResult: true,
	}, {
		name:       "ip_no_match",
		replHost:   filtertest.SafeBrowsingReplIPv4Str,
		host:       testOtherHost,
		wantRule:   "",
		qType:      dns.TypeA,
		wantResult: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFilter(t, tc.replHost)

			req := dnsservertest.NewReq(
				dns.Fqdn(tc.host),
				tc.qType,
				dns.ClassINET,
			)
			ri := &agd.RequestInfo{
				Messages: agdtest.NewConstructor(),
				Host:     tc.host,
				QType:    tc.qType,
			}

			ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)

			r, err := f.FilterRequest(ctx, req, ri)
			require.NoError(t, err)

			var wantRes internal.Result
			if tc.wantResult {
				if tc.replHost == testReplHost {
					wantRes = newModReqResult(req, tc.wantRule)
				} else {
					wantRes = newModRespResult(t, req, ri.Messages, filtertest.SafeBrowsingReplIPv4)
				}
			}

			assert.Equal(t, wantRes, r)
		})
	}

	require.True(t, t.Run("cached_success", func(t *testing.T) {
		f := newFilter(t, testReplHost)

		req := dnsservertest.NewReq(
			dns.Fqdn(testHost),
			dns.TypeA,
			dns.ClassINET,
		)
		ri := &agd.RequestInfo{
			Messages: agdtest.NewConstructor(),
			Host:     testHost,
			QType:    dns.TypeA,
		}

		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)

		original, err := f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		cached, err := f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		// Do not check the ID as it is new for every clone.
		originalRM := testutil.RequireTypeAssert[*internal.ResultModifiedRequest](t, original)
		cachedRM := testutil.RequireTypeAssert[*internal.ResultModifiedRequest](t, cached)
		cachedRM.Msg.Id = originalRM.Msg.Id

		assert.Equal(t, cached, original)
	}))

	require.True(t, t.Run("cached_no_match", func(t *testing.T) {
		f := newFilter(t, testReplHost)

		req := dnsservertest.NewReq(
			dns.Fqdn(testOtherHost),
			dns.TypeA,
			dns.ClassINET,
		)
		ri := &agd.RequestInfo{
			Messages: agdtest.NewConstructor(),
			Host:     testOtherHost,
			QType:    dns.TypeA,
		}

		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)

		r, err := f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		cached, err := f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		assert.Equal(t, cached, r)
	}))

	require.True(t, t.Run("https", func(t *testing.T) {
		f := newFilter(t, testReplHost)

		req := dnsservertest.NewReq(dns.Fqdn(testHost), dns.TypeHTTPS, dns.ClassINET)
		ri := &agd.RequestInfo{
			Messages: agdtest.NewConstructor(),
			Host:     testHost,
			QType:    dns.TypeHTTPS,
		}

		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)

		r, err := f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)
		require.NotNil(t, r)

		assert.Equal(t, newModReqResult(req, testHost), r)
	}))

	require.True(t, t.Run("https_ip", func(t *testing.T) {
		f := newFilter(t, filtertest.SafeBrowsingReplIPv4Str)

		req := dnsservertest.NewReq(dns.Fqdn(testHost), dns.TypeHTTPS, dns.ClassINET)
		ri := &agd.RequestInfo{
			Messages: agdtest.NewConstructor(),
			Host:     testHost,
			QType:    dns.TypeHTTPS,
		}

		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)

		r, err := f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)
		require.NotNil(t, r)

		m := testutil.RequireTypeAssert[*internal.ResultModifiedResponse](t, r)
		require.NotNil(t, m.Msg)
		require.Len(t, m.Msg.Question, 1)

		assert.Equal(t, m.Msg.Question[0].Qtype, dns.TypeHTTPS)
		assert.Len(t, m.Msg.Answer, 0)
	}))
}

// newModRespResult is a helper for creating modified results for tests.
func newModRespResult(
	tb testing.TB,
	req *dns.Msg,
	messages *dnsmsg.Constructor,
	replIP netip.Addr,
) (r *internal.ResultModifiedResponse) {
	tb.Helper()

	resp, err := messages.NewIPRespMsg(req, replIP)
	require.NoError(tb, err)

	return &internal.ResultModifiedResponse{
		Msg:  resp,
		List: testFltListID,
		Rule: testHost,
	}
}

// newModReqResult is a helper for creating modified results for tests.
func newModReqResult(
	req *dns.Msg,
	rule agd.FilterRuleText,
) (r *internal.ResultModifiedRequest) {
	req = dnsmsg.Clone(req)
	req.Question[0].Name = dns.Fqdn(testReplHost)

	return &internal.ResultModifiedRequest{
		Msg:  req,
		List: testFltListID,
		Rule: rule,
	}
}

// newFilter is a helper constructor for tests.
func newFilter(tb testing.TB, replHost string) (f *hashprefix.Filter) {
	tb.Helper()

	cachePath, srvURL := filtertest.PrepareRefreshable(tb, nil, testHost, http.StatusOK)

	strg, err := hashprefix.NewStorage("")
	require.NoError(tb, err)

	f, err = hashprefix.NewFilter(&hashprefix.FilterConfig{
		Cloner: agdtest.NewCloner(),
		Hashes: strg,
		URL:    srvURL,
		ErrColl: &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, _ error) {
				panic("not implemented")
			},
		},
		ID:              agd.FilterListIDAdultBlocking,
		CachePath:       cachePath,
		ReplacementHost: replHost,
		Staleness:       filtertest.Staleness,
		CacheTTL:        filtertest.CacheTTL,
		CacheSize:       1,
		MaxSize:         filtertest.FilterMaxSize,
	})
	require.NoError(tb, err)

	return f
}

func TestFilter_Refresh(t *testing.T) {
	reqCh := make(chan struct{}, 1)
	cachePath, srvURL := filtertest.PrepareRefreshable(t, reqCh, testHost, http.StatusOK)

	strg, err := hashprefix.NewStorage("")
	require.NoError(t, err)

	f, err := hashprefix.NewFilter(&hashprefix.FilterConfig{
		Cloner: agdtest.NewCloner(),
		Hashes: strg,
		URL:    srvURL,
		ErrColl: &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, _ error) {
				panic("not implemented")
			},
		},
		ID:              agd.FilterListIDAdultBlocking,
		CachePath:       cachePath,
		ReplacementHost: testReplHost,
		Staleness:       filtertest.Staleness,
		CacheTTL:        filtertest.CacheTTL,
		CacheSize:       1,
		MaxSize:         filtertest.FilterMaxSize,
	})
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)

	err = f.Refresh(ctx)
	assert.NoError(t, err)

	testutil.RequireReceive(t, reqCh, filtertest.Timeout)
}

func TestFilter_FilterRequest_staleCache(t *testing.T) {
	refrCh := make(chan struct{}, 1)
	cachePath, srvURL := filtertest.PrepareRefreshable(t, refrCh, testHost, http.StatusOK)

	// Put some initial data into the cache to avoid the first refresh.

	cf, err := os.OpenFile(cachePath, os.O_WRONLY|os.O_APPEND, os.ModeAppend)
	require.NoError(t, err)

	_, err = cf.WriteString(testOtherHost)
	require.NoError(t, err)
	require.NoError(t, cf.Close())

	// Create the filter.

	strg, err := hashprefix.NewStorage("")
	require.NoError(t, err)

	fconf := &hashprefix.FilterConfig{
		Cloner: agdtest.NewCloner(),
		Hashes: strg,
		URL:    srvURL,
		ErrColl: &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, _ error) {
				panic("not implemented")
			},
		},
		ID:              agd.FilterListIDAdultBlocking,
		CachePath:       cachePath,
		ReplacementHost: testReplHost,
		Staleness:       filtertest.Staleness,
		CacheTTL:        filtertest.CacheTTL,
		CacheSize:       1,
		MaxSize:         filtertest.FilterMaxSize,
	}
	f, err := hashprefix.NewFilter(fconf)
	require.NoError(t, err)

	messages := agdtest.NewConstructor()

	// Test the following:
	//
	//  1. Check that the stale rules cache is used.
	//  2. Refresh the stale rules cache.
	//  3. Ensure the result cache is cleared.
	//  4. Ensure the stale rules aren't used.

	testHostReq := dnsservertest.NewReq(dns.Fqdn(testHost), dns.TypeA, dns.ClassINET)
	testReqInfo := &agd.RequestInfo{Messages: messages, Host: testHost, QType: dns.TypeA}

	testOtherHostReq := dnsservertest.NewReq(dns.Fqdn(testOtherHost), dns.TypeA, dns.ClassINET)
	testOtherReqInfo := &agd.RequestInfo{Messages: messages, Host: testOtherHost, QType: dns.TypeA}

	require.True(t, t.Run("hit_cached_host", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)

		var r internal.Result
		r, err = f.FilterRequest(ctx, testOtherHostReq, testOtherReqInfo)
		require.NoError(t, err)

		assert.Equal(t, newModReqResult(testOtherHostReq, testOtherHost), r)
	}))

	require.True(t, t.Run("refresh", func(t *testing.T) {
		// Make the cache stale.
		now := time.Now()
		err = os.Chtimes(cachePath, now, now.Add(-2*fconf.Staleness))
		require.NoError(t, err)

		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)

		err = f.Refresh(ctx)
		assert.NoError(t, err)

		testutil.RequireReceive(t, refrCh, filtertest.Timeout)
	}))

	require.True(t, t.Run("previously_cached", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)

		var r internal.Result
		r, err = f.FilterRequest(ctx, testOtherHostReq, testOtherReqInfo)
		require.NoError(t, err)

		assert.Nil(t, r)
	}))

	require.True(t, t.Run("new_host", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)

		var r internal.Result
		r, err = f.FilterRequest(ctx, testHostReq, testReqInfo)
		require.NoError(t, err)

		wantRes := newModReqResult(testHostReq, testHost)
		assert.Equal(t, wantRes, r)
	}))
}
