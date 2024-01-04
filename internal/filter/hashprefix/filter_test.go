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
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilter_FilterRequest(t *testing.T) {
	cachePath, srvURL := filtertest.PrepareRefreshable(t, nil, testHost, http.StatusOK)

	strg, err := hashprefix.NewStorage("")
	require.NoError(t, err)

	replIP := netip.MustParseAddr("1.2.3.4")
	f, err := hashprefix.NewFilter(&hashprefix.FilterConfig{
		Cloner: agdtest.NewCloner(),
		Hashes: strg,
		URL:    srvURL,
		ErrColl: &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, _ error) {
				panic("not implemented")
			},
		},
		Resolver: &agdtest.Resolver{
			OnLookupNetIP: func(
				_ context.Context,
				_ netutil.AddrFamily,
				_ string,
			) (ips []netip.Addr, err error) {
				return []netip.Addr{replIP}, nil
			},
		},
		ID:              agd.FilterListIDAdultBlocking,
		CachePath:       cachePath,
		ReplacementHost: "repl.example",
		Staleness:       filtertest.Staleness,
		CacheTTL:        filtertest.CacheTTL,
		CacheSize:       1,
		MaxSize:         filtertest.FilterMaxSize,
	})
	require.NoError(t, err)

	messages := agdtest.NewConstructor()

	testCases := []struct {
		name       string
		host       string
		qType      dnsmsg.RRType
		wantResult bool
	}{{
		name:       "not_a_or_aaaa",
		host:       testHost,
		qType:      dns.TypeTXT,
		wantResult: false,
	}, {
		name:       "success",
		host:       testHost,
		qType:      dns.TypeA,
		wantResult: true,
	}, {
		name:       "success_subdomain",
		host:       "a.b.c." + testHost,
		qType:      dns.TypeA,
		wantResult: true,
	}, {
		name:       "no_match",
		host:       testOtherHost,
		qType:      dns.TypeA,
		wantResult: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := dnsservertest.NewReq(
				dns.Fqdn(tc.host),
				tc.qType,
				dns.ClassINET,
			)
			ri := &agd.RequestInfo{
				Messages: messages,
				Host:     tc.host,
				QType:    tc.qType,
			}

			ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
			t.Cleanup(cancel)

			var r internal.Result
			r, err = f.FilterRequest(ctx, req, ri)
			require.NoError(t, err)

			if tc.wantResult {
				wantRes := newModifiedResult(t, req, messages, replIP)
				assert.Equal(t, wantRes, r)
			} else {
				assert.Nil(t, r)
			}
		})
	}

	t.Run("cached_success", func(t *testing.T) {
		req := dnsservertest.NewReq(
			dns.Fqdn(testHost),
			dns.TypeA,
			dns.ClassINET,
		)
		ri := &agd.RequestInfo{
			Messages: messages,
			Host:     testHost,
			QType:    dns.TypeA,
		}

		ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
		t.Cleanup(cancel)

		var r internal.Result
		r, err = f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		wantRes := newModifiedResult(t, req, messages, replIP)
		assert.Equal(t, wantRes, r)
	})

	t.Run("cached_no_match", func(t *testing.T) {
		req := dnsservertest.NewReq(
			dns.Fqdn(testOtherHost),
			dns.TypeA,
			dns.ClassINET,
		)
		ri := &agd.RequestInfo{
			Messages: messages,
			Host:     testOtherHost,
			QType:    dns.TypeA,
		}

		ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
		t.Cleanup(cancel)

		var r internal.Result
		r, err = f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)

		assert.Nil(t, r)
	})

	t.Run("https", func(t *testing.T) {
		req := dnsservertest.NewReq(dns.Fqdn(testHost), dns.TypeHTTPS, dns.ClassINET)
		ri := &agd.RequestInfo{
			Messages: messages,
			Host:     testHost,
			QType:    dns.TypeHTTPS,
		}

		ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
		t.Cleanup(cancel)

		var r internal.Result
		r, err = f.FilterRequest(ctx, req, ri)
		require.NoError(t, err)
		require.NotNil(t, r)

		m := testutil.RequireTypeAssert[*internal.ResultModified](t, r)
		require.NotNil(t, m.Msg)
		require.Len(t, m.Msg.Question, 1)

		assert.Equal(t, m.Msg.Question[0].Qtype, dns.TypeHTTPS)
		assert.Len(t, m.Msg.Answer, 0)
	})
}

// newModifiedResult is a helper for creating modified results for tests.
func newModifiedResult(
	tb testing.TB,
	req *dns.Msg,
	messages *dnsmsg.Constructor,
	replIP netip.Addr,
) (r *internal.ResultModified) {
	resp, err := messages.NewIPRespMsg(req, replIP)
	require.NoError(tb, err)

	return &internal.ResultModified{
		Msg:  resp,
		List: testFltListID,
		Rule: testHost,
	}
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
		Resolver: &agdtest.Resolver{
			OnLookupNetIP: func(
				_ context.Context,
				_ netutil.AddrFamily,
				_ string,
			) (ips []netip.Addr, err error) {
				panic("not implemented")
			},
		},
		ID:              agd.FilterListIDAdultBlocking,
		CachePath:       cachePath,
		ReplacementHost: "",
		Staleness:       filtertest.Staleness,
		CacheTTL:        filtertest.CacheTTL,
		CacheSize:       1,
		MaxSize:         filtertest.FilterMaxSize,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
	t.Cleanup(cancel)

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

	replIP := netip.MustParseAddr("1.2.3.4")
	fconf := &hashprefix.FilterConfig{
		Cloner: agdtest.NewCloner(),
		Hashes: strg,
		URL:    srvURL,
		ErrColl: &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, _ error) {
				panic("not implemented")
			},
		},
		Resolver: &agdtest.Resolver{
			OnLookupNetIP: func(
				_ context.Context,
				_ netutil.AddrFamily,
				_ string,
			) (ips []netip.Addr, err error) {
				return []netip.Addr{replIP}, nil
			},
		},
		ID:              agd.FilterListIDAdultBlocking,
		CachePath:       cachePath,
		ReplacementHost: "repl.example",
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

	t.Run("hit_cached_host", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
		t.Cleanup(cancel)

		var r internal.Result
		r, err = f.FilterRequest(ctx, testOtherHostReq, testOtherReqInfo)
		require.NoError(t, err)

		var resp *dns.Msg
		resp, err = messages.NewIPRespMsg(testOtherHostReq, replIP)
		require.NoError(t, err)

		assert.Equal(t, &internal.ResultModified{
			Msg:  resp,
			List: testFltListID,
			Rule: testOtherHost,
		}, r)
	})

	t.Run("refresh", func(t *testing.T) {
		// Make the cache stale.
		now := time.Now()
		err = os.Chtimes(cachePath, now, now.Add(-2*fconf.Staleness))
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
		t.Cleanup(cancel)

		err = f.Refresh(ctx)
		assert.NoError(t, err)

		testutil.RequireReceive(t, refrCh, filtertest.Timeout)
	})

	t.Run("previously_cached", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
		t.Cleanup(cancel)

		var r internal.Result
		r, err = f.FilterRequest(ctx, testOtherHostReq, testOtherReqInfo)
		require.NoError(t, err)

		assert.Nil(t, r)
	})

	t.Run("new_host", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
		t.Cleanup(cancel)

		var r internal.Result
		r, err = f.FilterRequest(ctx, testHostReq, testReqInfo)
		require.NoError(t, err)

		wantRes := newModifiedResult(t, testHostReq, messages, replIP)
		assert.Equal(t, wantRes, r)
	})
}
