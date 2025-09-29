package safesearch_test

import (
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/safesearch"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSafeIPStr is the string representation of the IP address of the safe
// version of [testEngineWithIP].
const testSafeIPStr = "1.2.3.4"

// testIPOfEngineWithIP is the IP address of the safe version of
// search-engine-ip.example.
var testIPOfEngineWithIP = netip.MustParseAddr(testSafeIPStr)

// Common domain names for tests.
const (
	testOther            = "other.example"
	testEngineWithIP     = "search-engine-ip.example"
	testEngineWithDomain = "search-engine-domain.example"
	testSafeDomain       = "safe-search-engine-domain.example"
)

// testFilterRules is are common filtering rules for tests.
const testFilterRules = `|` + testEngineWithIP + `^$dnsrewrite=NOERROR;A;` + testSafeIPStr + "\n" +
	`|` + testEngineWithDomain + `^$dnsrewrite=NOERROR;CNAME;` + testSafeDomain

func TestFilter(t *testing.T) {
	f := newTestFilter(t)

	require.True(t, t.Run("no_match", func(t *testing.T) {
		req := newRequest(t, testOther, dns.TypeA)
		res := filterRequest(t, f, req)

		assert.Nil(t, res)

		require.True(t, t.Run("cached", func(t *testing.T) {
			res = filterRequest(t, f, req)

			// TODO(a.garipov): Find a way to make caches more inspectable.
			assert.Nil(t, res)
		}))
	}))

	require.True(t, t.Run("txt", func(t *testing.T) {
		req := newRequest(t, testEngineWithIP, dns.TypeTXT)
		res := filterRequest(t, f, req)

		assert.Nil(t, res)
	}))

	require.True(t, t.Run("ip", func(t *testing.T) {
		req := newRequest(t, testEngineWithIP, dns.TypeA)
		res := filterRequest(t, f, req)

		rm := testutil.RequireTypeAssert[*filter.ResultModifiedResponse](t, res)
		require.Len(t, rm.Msg.Answer, 1)

		assert.Equal(t, rm.Rule, filter.RuleText(testEngineWithIP))

		a := testutil.RequireTypeAssert[*dns.A](t, rm.Msg.Answer[0])
		assert.Equal(t, net.IP(testIPOfEngineWithIP.AsSlice()), a.A)

		t.Run("cached", func(t *testing.T) {
			newReq := newRequest(t, testEngineWithIP, dns.TypeA)

			cachedRes := filterRequest(t, f, newReq)

			// Do not assert that the results are the same, since a modified
			// result of a safe search is always cloned.  But assert that the
			// non-clonable fields are equal and that the message has reply
			// fields set properly.
			cachedMR := testutil.RequireTypeAssert[*filter.ResultModifiedResponse](t, cachedRes)
			assert.NotSame(t, cachedMR, rm)
			assert.Equal(t, cachedMR.Msg.Id, newReq.DNS.Id)
			assert.Equal(t, cachedMR.List, rm.List)
			assert.Equal(t, cachedMR.Rule, rm.Rule)
		})
	}))

	require.True(t, t.Run("domain", func(t *testing.T) {
		req := newRequest(t, testEngineWithDomain, dns.TypeA)
		res := filterRequest(t, f, req)

		rm := testutil.RequireTypeAssert[*filter.ResultModifiedRequest](t, res)
		require.NotNil(t, rm.Msg)
		require.Len(t, rm.Msg.Question, 1)

		assert.False(t, rm.Msg.Response)
		assert.Equal(t, rm.Rule, filter.RuleText(testEngineWithDomain))

		q := rm.Msg.Question[0]
		assert.Equal(t, dns.TypeA, q.Qtype)
		assert.Equal(t, dns.Fqdn(testSafeDomain), q.Name)
	}))

	require.True(t, t.Run("https", func(t *testing.T) {
		req := newRequest(t, testEngineWithDomain, dns.TypeHTTPS)
		res := filterRequest(t, f, req)

		rm := testutil.RequireTypeAssert[*filter.ResultModifiedRequest](t, res)
		require.NotNil(t, rm.Msg)
		require.Len(t, rm.Msg.Question, 1)

		assert.False(t, rm.Msg.Response)
		assert.Equal(t, rm.Rule, filter.RuleText(testEngineWithDomain))

		q := rm.Msg.Question[0]
		assert.Equal(t, dns.TypeHTTPS, q.Qtype)
		assert.Equal(t, dns.Fqdn(testSafeDomain), q.Name)
	}))
}

// filterRequest is a helper that calls [safesearch.Filter.FilterRequestUF].
func filterRequest(tb testing.TB, f *safesearch.Filter, req *filter.Request) (res filter.Result) {
	tb.Helper()

	ctx := testutil.ContextWithTimeout(tb, filtertest.Timeout)
	res, err := f.FilterRequestUF(ctx, req, &urlfilter.DNSRequest{}, &urlfilter.DNSResult{})
	require.NoError(tb, err)

	return res
}

func BenchmarkFilter_FilterRequestUF(b *testing.B) {
	const qt = dns.TypeA

	f := newTestFilter(b)

	b.Run("no_match", func(b *testing.B) {
		ctx := testutil.ContextWithTimeout(b, filtertest.Timeout)
		req := newRequest(b, testOther, qt)

		ufReq := &urlfilter.DNSRequest{
			Hostname: req.Host,
			DNSType:  qt,
		}

		ufRes := &urlfilter.DNSResult{}

		// Warmup to fill the slices.
		res, err := f.FilterRequestUF(ctx, req, ufReq, ufRes)
		require.NoError(b, err)
		require.Nil(b, res)

		b.ReportAllocs()
		for b.Loop() {
			ufRes.Reset()
			res, err = f.FilterRequestUF(ctx, req, ufReq, ufRes)
		}

		require.NoError(b, err)
		require.Nil(b, res)
	})

	b.Run("ip", func(b *testing.B) {
		ctx := testutil.ContextWithTimeout(b, filtertest.Timeout)
		req := newRequest(b, testEngineWithIP, qt)

		ufReq := &urlfilter.DNSRequest{
			Hostname: req.Host,
			DNSType:  qt,
		}

		ufRes := &urlfilter.DNSResult{}

		// Warmup to fill the slices.
		res, err := f.FilterRequestUF(ctx, req, ufReq, ufRes)
		require.NoError(b, err)
		require.NotNil(b, res)

		b.ReportAllocs()
		for b.Loop() {
			ufRes.Reset()
			res, err = f.FilterRequestUF(ctx, req, ufReq, ufRes)
		}

		require.NoError(b, err)
		require.NotNil(b, res)
	})

	b.Run("domain", func(b *testing.B) {
		ctx := testutil.ContextWithTimeout(b, filtertest.Timeout)
		req := newRequest(b, testEngineWithDomain, qt)

		ufReq := &urlfilter.DNSRequest{
			Hostname: req.Host,
			DNSType:  qt,
		}

		ufRes := &urlfilter.DNSResult{}

		// Warmup to fill the slices.
		res, err := f.FilterRequestUF(ctx, req, ufReq, ufRes)
		require.NoError(b, err)
		require.NotNil(b, res)

		b.ReportAllocs()
		for b.Loop() {
			ufRes.Reset()
			res, err = f.FilterRequestUF(ctx, req, ufReq, ufRes)
		}

		require.NoError(b, err)
		require.NotNil(b, res)
	})

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/safesearch
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkFilter_FilterRequestUF/no_match-16       	18863545	        62.65 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkFilter_FilterRequestUF/ip-16             	 1516423	       784.0 ns/op	     664 B/op	      10 allocs/op
	//	BenchmarkFilter_FilterRequestUF/domain-16         	 2859573	       424.6 ns/op	     320 B/op	       6 allocs/op
}

// newTestFilter creates a new [*safesearch.Filter] for testing, and refreshes
// it immediately.
func newTestFilter(tb testing.TB) (f *safesearch.Filter) {
	tb.Helper()

	reqCh := make(chan struct{}, 1)
	cachePath, srvURL := filtertest.PrepareRefreshable(tb, reqCh, testFilterRules, http.StatusOK)

	f, err := safesearch.New(
		&safesearch.Config{
			Refreshable: &refreshable.Config{
				Logger:    slogutil.NewDiscardLogger(),
				ID:        filter.IDGeneralSafeSearch,
				URL:       srvURL,
				CachePath: cachePath,
				Staleness: filtertest.Staleness,
				Timeout:   filtertest.Timeout,
				MaxSize:   filtertest.FilterMaxSize,
			},
			CacheTTL: 1 * time.Minute,
		},
		rulelist.NewResultCache(filtertest.CacheCount, true),
	)
	require.NoError(tb, err)

	err = f.Refresh(testutil.ContextWithTimeout(tb, filtertest.Timeout), true)
	require.NoError(tb, err)

	testutil.RequireReceive(tb, reqCh, filtertest.Timeout)

	return f
}

// newRequest is a test helper that returns the filtering request with the given
// data.
func newRequest(tb testing.TB, host string, qt dnsmsg.RRType) (req *filter.Request) {
	tb.Helper()

	return &filter.Request{
		DNS:      dnsservertest.NewReq(host, qt, dns.ClassINET),
		Messages: agdtest.NewConstructor(tb),
		Host:     host,
		QType:    qt,
		QClass:   dns.ClassINET,
	}
}
