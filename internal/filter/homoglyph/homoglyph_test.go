package homoglyph_test

import (
	"cmp"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdalg"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/homoglyph"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Common indexes for tests.
var (
	testIndex = &filterindex.Homoglyph{
		Domains: []*filterindex.HomoglyphProtectedDomain{{
			Domain: filtertest.Host,
		}},
		Exceptions: nil,
	}
	testIndexExc = &filterindex.Homoglyph{
		Domains: []*filterindex.HomoglyphProtectedDomain{{
			Domain: filtertest.Host,
		}},
		Exceptions: []*filterindex.HomoglyphException{{
			Domain: filtertest.HostHomographDomainExc,
		}},
	}
)

func TestFilter_FilterRequest_basic(t *testing.T) {
	t.Parallel()

	f := newTestFilter(t, &homoglyph.Config{
		Storage: newTestStorage(testIndex),
	})

	testCases := []struct {
		name         string
		host         string
		qtype        dnsmsg.RRType
		wantFiltered bool
	}{{
		name:         "exact_match",
		host:         filtertest.Host,
		qtype:        dns.TypeA,
		wantFiltered: false,
	}, {
		name:         "homograph_one_char",
		host:         filtertest.HostHomographDomain,
		qtype:        dns.TypeA,
		wantFiltered: true,
	}, {
		name:         "subdomain",
		host:         "mail." + filtertest.Host,
		qtype:        dns.TypeA,
		wantFiltered: false,
	}, {
		name:         "subdomain_homograph",
		host:         "mail." + filtertest.HostHomographDomain,
		qtype:        dns.TypeA,
		wantFiltered: true,
	}, {
		name:         "aaaa_query",
		host:         filtertest.HostHomographDomain,
		qtype:        dns.TypeAAAA,
		wantFiltered: true,
	}, {
		name:         "https_query",
		host:         filtertest.HostHomographDomain,
		qtype:        dns.TypeHTTPS,
		wantFiltered: true,
	}, {
		name:         "txt_query_not_filtered",
		host:         filtertest.HostHomographDomain,
		qtype:        dns.TypeTXT,
		wantFiltered: false,
	}, {
		name:         "mx_query_not_filtered",
		host:         filtertest.HostHomographDomain,
		qtype:        dns.TypeMX,
		wantFiltered: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := newTestRequest(t, tc.host, tc.qtype)
			var want filter.Result
			if tc.wantFiltered {
				want = newTestResult(t, req.DNS, filtertest.Host)
			}

			ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
			res, err := f.FilterRequest(ctx, req)
			require.NoError(t, err)

			filtertest.AssertEqualResult(t, want, res)
		})
	}
}

// newTestStorage returns a test storage that returns the given index.
func newTestStorage(fltIdx *filterindex.Homoglyph) (s *agdtest.FilterIndexStorage) {
	return &agdtest.FilterIndexStorage{
		OnTyposquatting: func(ctx context.Context) (_ *filterindex.Typosquatting, _ error) {
			panic(testutil.UnexpectedCall(ctx))
		},
		OnHomoglyph: func(_ context.Context) (idx *filterindex.Homoglyph, err error) {
			return fltIdx, nil
		},
	}
}

// newTestFilter creates homoglyph filters for tests.  c may be nil, and all
// zero-value fields in c are replaced with defaults for tests.
func newTestFilter(tb testing.TB, c *homoglyph.Config) (f *homoglyph.Filter) {
	tb.Helper()

	c = cmp.Or(c, &homoglyph.Config{})

	c.Cloner = cmp.Or(c.Cloner, agdtest.NewCloner())
	c.Logger = cmp.Or(c.Logger, filtertest.Logger)

	c.CacheManager = cmp.Or[agdcache.Manager](c.CacheManager, agdcache.EmptyManager{})
	c.Clock = cmp.Or[timeutil.Clock](c.Clock, timeutil.SystemClock{})
	c.ErrColl = cmp.Or[errcoll.Interface](c.ErrColl, agdtest.NewErrorCollector())
	c.Metrics = cmp.Or[filter.Metrics](c.Metrics, filter.EmptyMetrics{})
	c.PublicSuffixList = cmp.Or(c.PublicSuffixList, publicsuffix.List)
	c.Storage = cmp.Or[filterindex.Storage](c.Storage, filterindex.EmptyStorage{})

	if c.CachePath == "" {
		c.CachePath = filepath.Join(tb.TempDir(), "homoglyph.json")
	}

	c.ResultListID = cmp.Or(c.ResultListID, filter.IDHomoglyph)

	c.Staleness = cmp.Or(c.Staleness, filtertest.Staleness)

	c.CacheCount = cmp.Or(c.CacheCount, filtertest.CacheCount)

	if c.ReplacedResultConstructor == nil {
		var err error
		c.ReplacedResultConstructor, err = filter.NewReplacedResultConstructor(
			&filter.ReplacedResultConstructorConfig{
				Cloner:      c.Cloner,
				Replacement: filtertest.HostDangerousRepl,
			},
		)
		require.NoError(tb, err)
	}

	f = homoglyph.New(c)

	ctx := testutil.ContextWithTimeout(tb, filtertest.Timeout)
	err := f.RefreshInitial(ctx)
	require.NoError(tb, err)

	return f
}

// newTestRequest creates a new filter request for tests.
func newTestRequest(tb testing.TB, host string, qtype dnsmsg.RRType) (req *filter.Request) {
	tb.Helper()

	return filtertest.NewRequest(tb, "", host, filtertest.IPv4Client, qtype)
}

// newTestResult creates a new filter result for tests.  req must not be nil.
func newTestResult(
	tb testing.TB,
	req *dns.Msg,
	rule filter.RuleText,
) (res *filter.ResultModifiedRequest) {
	tb.Helper()

	require.NotNil(tb, req)

	return filtertest.NewModifiedRequestResult(
		tb,
		req,
		filtertest.FQDNDangerousRepl,
		rule,
		filter.IDHomoglyph,
	)
}

func TestFilter_FilterRequest_exceptions(t *testing.T) {
	t.Parallel()

	f := newTestFilter(t, &homoglyph.Config{
		Storage: newTestStorage(testIndexExc),
	})

	testCases := []struct {
		name         string
		host         string
		wantFiltered bool
	}{{
		name:         "exception_exact",
		host:         filtertest.HostHomographDomainExc,
		wantFiltered: false,
	}, {
		name:         "exception_subdomain",
		host:         "mail." + filtertest.HostHomographDomainExc,
		wantFiltered: false,
	}, {
		name:         "not_exception",
		host:         filtertest.HostHomographDomain,
		wantFiltered: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := newTestRequest(t, tc.host, dns.TypeA)

			var want filter.Result
			if tc.wantFiltered {
				want = newTestResult(t, req.DNS, filtertest.Host)
			}

			ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
			res, err := f.FilterRequest(ctx, req)
			require.NoError(t, err)

			assert.Equal(t, want, res)
		})
	}
}

func TestFilter_FilterRequest_multiple(t *testing.T) {
	t.Parallel()

	const (
		anotherProtectedDomain = "another.example"
		anotherHomographDomain = "аnother.example"
	)

	idx := &filterindex.Homoglyph{
		Domains: []*filterindex.HomoglyphProtectedDomain{{
			Domain: filtertest.Host,
		}, {
			Domain: anotherProtectedDomain,
		}},
		Exceptions: nil,
	}

	f := newTestFilter(t, &homoglyph.Config{
		Storage: newTestStorage(idx),
	})

	testCases := []struct {
		req      *filter.Request
		name     string
		wantRule filter.RuleText
	}{{
		req:      newTestRequest(t, filtertest.Host, dns.TypeA),
		name:     "not_homograph",
		wantRule: "",
	}, {
		req:      newTestRequest(t, anotherProtectedDomain, dns.TypeA),
		name:     "not_homograph_another",
		wantRule: "",
	}, {
		req:      newTestRequest(t, filtertest.HostHomographDomain, dns.TypeA),
		name:     "homograph",
		wantRule: filtertest.Host,
	}, {
		req:      newTestRequest(t, anotherHomographDomain, dns.TypeA),
		name:     "homograph_another",
		wantRule: anotherProtectedDomain,
	}, {
		req:      newTestRequest(t, "test"+filtertest.Host, dns.TypeA),
		name:     "miss",
		wantRule: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
			res, err := f.FilterRequest(ctx, tc.req)
			require.NoError(t, err)

			var want filter.Result
			if tc.wantRule != "" {
				want = newTestResult(t, tc.req.DNS, tc.wantRule)
			}

			assert.Equal(t, want, res)
		})
	}
}

func TestFilter_FilterRequest_emptyIndex(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		idx        *filterindex.Homoglyph
		name       string
		wantErrMsg string
	}{{
		idx: &filterindex.Homoglyph{
			Domains:    nil,
			Exceptions: nil,
		},
		name: "nil_domains",
	}, {
		idx: &filterindex.Homoglyph{
			Domains:    []*filterindex.HomoglyphProtectedDomain{},
			Exceptions: nil,
		},
		name: "empty_domains",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newTestFilter(t, &homoglyph.Config{
				Storage: newTestStorage(tc.idx),
			})
			req := newTestRequest(t, filtertest.HostHomographDomainExc, dns.TypeA)

			ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
			res, err := f.FilterRequest(ctx, req)
			require.NoError(t, err)

			assert.Nil(t, res)
		})
	}
}

func TestFilter_FilterRequest_cache(t *testing.T) {
	t.Parallel()

	f := newTestFilter(t, &homoglyph.Config{
		Storage: newTestStorage(testIndex),
	})

	var cachedRes filter.Result
	var err error

	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)

	require.True(t, t.Run("calc_and_cache", func(t *testing.T) {
		req := newTestRequest(t, filtertest.HostHomographDomain, dns.TypeA)

		cachedRes, err = f.FilterRequest(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, cachedRes)
	}))

	require.True(t, t.Run("hit", func(t *testing.T) {
		req := newTestRequest(t, filtertest.HostHomographDomain, dns.TypeA)

		var res filter.Result
		res, err = f.FilterRequest(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, res)

		assert.NotSame(t, cachedRes, res)
	}))

	require.True(t, t.Run("miss", func(t *testing.T) {
		reqAAAA := newTestRequest(t, filtertest.HostHomographDomain, dns.TypeAAAA)

		var res filter.Result
		res, err = f.FilterRequest(ctx, reqAAAA)
		require.NoError(t, err)
		require.NotNil(t, res)

		assert.NotSame(t, cachedRes, res)
	}))
}

func FuzzFilter_FilterRequest(f *testing.F) {
	idx := &filterindex.Homoglyph{
		Domains: []*filterindex.HomoglyphProtectedDomain{{
			Domain: filtertest.Host,
		}, {
			Domain: "another.example",
		}, {
			Domain: "third.example",
		}},
		Exceptions: []*filterindex.HomoglyphException{{
			Domain: filtertest.HostHomographDomainExc,
		}},
	}

	c := agdalg.NewSkeletonConstructor(netutil.MaxDomainNameLen, netutil.MaxDomainNameLen)

	conf := &homoglyph.Config{
		Storage: newTestStorage(idx),
	}

	flt := newTestFilter(f, conf)

	for _, seed := range []string{
		filtertest.HostHomographDomain,
		filtertest.HostHomographDomainExc,
		filtertest.Host,
		"tset.example",
		"google.com",
		"gogle.com",
		"gooogle.com",
		"a.b",
		"com",
		"x",
		"mail." + filtertest.Host,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, host string) {
		host, err := idna.ToASCII(host)
		if err != nil {
			// Skip invalid ASCII, because the filter doesn't receive it.
			return
		}

		req := newTestRequest(t, host, dns.TypeA)

		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
		res, err := flt.FilterRequest(ctx, req)
		require.NoError(t, err)

		if res != nil {
			modReq := testutil.RequireTypeAssert[*filter.ResultModifiedRequest](t, res)

			ruleStr := string(modReq.Rule)
			assert.Contains(t, idx.Domains, &filterindex.HomoglyphProtectedDomain{
				Domain: ruleStr,
			})

			unicodeHost, idnaErr := idna.ToUnicode(host)
			require.NoError(t, idnaErr)

			etld1, etldErr := agdnet.EffectiveTLDPlusOne(conf.PublicSuffixList, unicodeHost)
			require.NoError(t, etldErr)

			assert.Equalf(
				t,
				c.Skeleton(etld1),
				c.Skeleton(ruleStr),
				"original: etld+1: %q, rule: %q",
				etld1,
				ruleStr,
			)
		}
	})
}

func BenchmarkFilter_FilterRequest(b *testing.B) {
	// Create a realistic index with many protected domains.
	domains := make([]*filterindex.HomoglyphProtectedDomain, 0, 1000)
	for i := range 1000 {
		domains = append(domains, &filterindex.HomoglyphProtectedDomain{
			Domain: fmt.Sprintf("test%v.example", i),
		})
	}

	idx := &filterindex.Homoglyph{
		Domains:    domains,
		Exceptions: nil,
	}

	f := newTestFilter(b, &homoglyph.Config{
		Storage: newTestStorage(idx),
	})

	b.Run("correct", func(b *testing.B) {
		// Not an IDN.
		req := newTestRequest(b, domains[0].Domain, dns.TypeA)

		// Warmup to fill the cache.
		ctx := b.Context()
		res, err := f.FilterRequest(ctx, req)
		require.NoError(b, err)
		require.Nil(b, res)

		b.ReportAllocs()

		for b.Loop() {
			res, err = f.FilterRequest(ctx, req)
		}

		require.NoError(b, err)

		assert.Nil(b, res)
	})

	b.Run("hit_homograph", func(b *testing.B) {
		domain, err := idna.ToASCII(strings.ReplaceAll(domains[0].Domain, "a", "а"))
		require.NoError(b, err)

		req := newTestRequest(b, domain, dns.TypeA)
		want := newTestResult(b, req.DNS, filter.RuleText(domains[0].Domain))

		// Warmup to fill the cache.
		ctx := b.Context()
		res, err := f.FilterRequest(ctx, req)
		require.NoError(b, err)
		filtertest.AssertEqualResult(b, want, res)

		b.ReportAllocs()

		for b.Loop() {
			res, err = f.FilterRequest(ctx, req)
		}

		require.NoError(b, err)

		filtertest.AssertEqualResult(b, want, res)
	})

	b.Run("miss", func(b *testing.B) {
		// Not an IDN.
		req := newTestRequest(b, "nonexistent.example", dns.TypeA)

		// Warmup to fill the cache.
		ctx := b.Context()
		res, err := f.FilterRequest(ctx, req)
		require.NoError(b, err)
		require.Nil(b, res)

		b.ReportAllocs()

		for b.Loop() {
			res, err = f.FilterRequest(ctx, req)
		}

		require.NoError(b, err)

		assert.Nil(b, res)
	})

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/homoglyph
	//	cpu: Apple M4 Pro
	//	BenchmarkFilter_FilterRequest/correct-14         	 7528288	       146.4 ns/op	      72 B/op	       2 allocs/op
	//	BenchmarkFilter_FilterRequest/hit_homograph-14   	 3192362	       374.6 ns/op	     400 B/op	      10 allocs/op
	//	BenchmarkFilter_FilterRequest/miss-14            	 8216628	       144.8 ns/op	      72 B/op	       2 allocs/op
}
