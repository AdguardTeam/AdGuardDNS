package typosquatting_test

import (
	"cmp"
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/typosquatting"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/publicsuffix"
)

// Common domains for tests.
const (
	testExceptionDomain = "a" + filtertest.HostTypoProtectedDomain
)

// Common indexes for tests.
var (
	testIndex = &filterindex.Typosquatting{
		Domains: []*filterindex.TyposquattingProtectedDomain{{
			Domain:   filtertest.HostTypoProtectedDomain,
			Distance: 1,
		}},
		Exceptions: nil,
	}
	testIndexExc = &filterindex.Typosquatting{
		Domains: []*filterindex.TyposquattingProtectedDomain{{
			Domain:   filtertest.HostTypoProtectedDomain,
			Distance: 1,
		}},
		Exceptions: []*filterindex.TyposquattingException{{
			Domain: testExceptionDomain,
		}},
	}
)

func TestFilter_FilterRequest_basic(t *testing.T) {
	t.Parallel()

	f := newTestFilter(t, &typosquatting.Config{
		Storage: newTestStorage(testIndex),
	})

	testCases := []struct {
		name         string
		host         string
		qtype        dnsmsg.RRType
		wantFiltered bool
	}{{
		name:         "exact_match",
		host:         filtertest.HostTypoProtectedDomain,
		qtype:        dns.TypeA,
		wantFiltered: false,
	}, {
		name:         "typo_one_char",
		host:         filtertest.HostTypoDomain,
		qtype:        dns.TypeA,
		wantFiltered: true,
	}, {
		name:         "typo_one_char_extra",
		host:         "e" + filtertest.HostTypoProtectedDomain,
		qtype:        dns.TypeA,
		wantFiltered: true,
	}, {
		name: "typo_transposition",
		host: filtertest.HostTypoProtectedDomain[1:2] +
			filtertest.HostTypoProtectedDomain[0:1] +
			filtertest.HostTypoProtectedDomain[2:],
		qtype:        dns.TypeA,
		wantFiltered: true,
	}, {
		name:         "too_far_two_chars",
		host:         "example.org",
		qtype:        dns.TypeA,
		wantFiltered: false,
	}, {
		name:         "another_domain",
		host:         "test.sample",
		qtype:        dns.TypeA,
		wantFiltered: false,
	}, {
		name:         "subdomain",
		host:         "mail." + filtertest.HostTypoProtectedDomain,
		qtype:        dns.TypeA,
		wantFiltered: false,
	}, {
		name:         "subdomain_typo",
		host:         "mail." + filtertest.HostTypoDomain,
		qtype:        dns.TypeA,
		wantFiltered: true,
	}, {
		name:         "aaaa_query",
		host:         filtertest.HostTypoDomain,
		qtype:        dns.TypeAAAA,
		wantFiltered: true,
	}, {
		name:         "https_query",
		host:         filtertest.HostTypoDomain,
		qtype:        dns.TypeHTTPS,
		wantFiltered: true,
	}, {
		name:         "txt_query_not_filtered",
		host:         filtertest.HostTypoDomain,
		qtype:        dns.TypeTXT,
		wantFiltered: false,
	}, {
		name:         "mx_query_not_filtered",
		host:         filtertest.HostTypoDomain,
		qtype:        dns.TypeMX,
		wantFiltered: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := newTestRequest(t, tc.host, tc.qtype)
			var want filter.Result
			if tc.wantFiltered {
				want = newTestResult(t, req.DNS, filtertest.HostTypoProtectedDomain)
			}

			ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
			res, err := f.FilterRequest(ctx, req)
			require.NoError(t, err)

			filtertest.AssertEqualResult(t, want, res)
		})
	}
}

// newTestStorage returns a test storage that returns the given index.
func newTestStorage(fltIdx *filterindex.Typosquatting) (s *agdtest.FilterIndexStorage) {
	return &agdtest.FilterIndexStorage{
		OnTyposquatting: func(_ context.Context) (idx *filterindex.Typosquatting, err error) {
			return fltIdx, nil
		},
	}
}

// newTestFilter creates typosquatting filters for tests.  c may be nil, and all
// zero-value fields in c are replaced with defaults for tests.
func newTestFilter(tb testing.TB, c *typosquatting.Config) (f *typosquatting.Filter) {
	tb.Helper()

	c = cmp.Or(c, &typosquatting.Config{})

	c.Cloner = cmp.Or(c.Cloner, agdtest.NewCloner())
	c.Logger = cmp.Or(c.Logger, filtertest.Logger)

	c.CacheManager = cmp.Or[agdcache.Manager](c.CacheManager, agdcache.EmptyManager{})
	c.Clock = cmp.Or[timeutil.Clock](c.Clock, timeutil.SystemClock{})
	c.ErrColl = cmp.Or[errcoll.Interface](c.ErrColl, agdtest.NewErrorCollector())
	c.Metrics = cmp.Or[filter.Metrics](c.Metrics, filter.EmptyMetrics{})
	c.PublicSuffixList = cmp.Or(c.PublicSuffixList, publicsuffix.List)
	c.Storage = cmp.Or[filterindex.Storage](c.Storage, filterindex.EmptyStorage{})

	if c.CachePath == "" {
		c.CachePath = filepath.Join(tb.TempDir(), "typosquatting.json")
	}

	c.ResultListID = cmp.Or(c.ResultListID, filter.IDTyposquatting)

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

	f = typosquatting.New(c)

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
		filter.IDTyposquatting,
	)
}

func TestFilter_FilterRequest_exceptions(t *testing.T) {
	t.Parallel()

	f := newTestFilter(t, &typosquatting.Config{
		Storage: newTestStorage(testIndexExc),
	})

	testCases := []struct {
		name         string
		host         string
		wantFiltered bool
	}{{
		name:         "exception_exact",
		host:         testExceptionDomain,
		wantFiltered: false,
	}, {
		name:         "exception_subdomain",
		host:         "mail." + testExceptionDomain,
		wantFiltered: false,
	}, {
		name:         "not_exception",
		host:         filtertest.HostTypoDomain,
		wantFiltered: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := newTestRequest(t, tc.host, dns.TypeA)

			var want filter.Result
			if tc.wantFiltered {
				want = newTestResult(t, req.DNS, filtertest.HostTypoProtectedDomain)
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
		anotherProtectedDomain = "a" + filtertest.HostTypoProtectedDomain
		anotherTypoDomain      = "aa" + filtertest.HostTypoProtectedDomain
	)

	idx := &filterindex.Typosquatting{
		Domains: []*filterindex.TyposquattingProtectedDomain{{
			Domain:   filtertest.HostTypoProtectedDomain,
			Distance: 2,
		}, {
			Domain:   anotherProtectedDomain,
			Distance: 2,
		}},
		Exceptions: nil,
	}

	f := newTestFilter(t, &typosquatting.Config{
		Storage: newTestStorage(idx),
	})

	testCases := []struct {
		req      *filter.Request
		name     string
		wantRule filter.RuleText
	}{{
		req:      newTestRequest(t, filtertest.HostTypoProtectedDomain, dns.TypeA),
		name:     "no_typo",
		wantRule: "",
	}, {
		req:      newTestRequest(t, anotherProtectedDomain, dns.TypeA),
		name:     "no_typo_another",
		wantRule: "",
	}, {
		req:      newTestRequest(t, filtertest.HostTypoDomain, dns.TypeA),
		name:     "typo",
		wantRule: filtertest.HostTypoProtectedDomain,
	}, {
		req:      newTestRequest(t, anotherTypoDomain, dns.TypeA),
		name:     "typo_another",
		wantRule: anotherProtectedDomain,
	}, {
		req:      newTestRequest(t, "tt"+anotherTypoDomain, dns.TypeA),
		name:     "typo_another_too_far",
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
		idx        *filterindex.Typosquatting
		name       string
		wantErrMsg string
	}{{
		idx: &filterindex.Typosquatting{
			Domains:    nil,
			Exceptions: nil,
		},
		name: "nil_domains",
	}, {
		idx: &filterindex.Typosquatting{
			Domains:    []*filterindex.TyposquattingProtectedDomain{},
			Exceptions: nil,
		},
		name: "empty_domains",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newTestFilter(t, &typosquatting.Config{
				Storage: newTestStorage(tc.idx),
			})
			req := newTestRequest(t, filtertest.HostTypoProtectedDomain, dns.TypeA)

			ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
			res, err := f.FilterRequest(ctx, req)
			require.NoError(t, err)

			assert.Nil(t, res)
		})
	}
}

func TestFilter_FilterRequest_cache(t *testing.T) {
	t.Parallel()

	f := newTestFilter(t, &typosquatting.Config{
		Storage: newTestStorage(testIndex),
	})

	var cachedRes filter.Result
	var err error

	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)

	require.True(t, t.Run("calc_and_cache", func(t *testing.T) {
		req := newTestRequest(t, filtertest.HostTypoDomain, dns.TypeA)

		cachedRes, err = f.FilterRequest(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, cachedRes)
	}))

	require.True(t, t.Run("hit", func(t *testing.T) {
		req := newTestRequest(t, filtertest.HostTypoDomain, dns.TypeA)

		var res filter.Result
		res, err = f.FilterRequest(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, res)

		assert.NotSame(t, cachedRes, res)
	}))

	require.True(t, t.Run("miss", func(t *testing.T) {
		reqAAAA := newTestRequest(t, filtertest.HostTypoDomain, dns.TypeAAAA)

		var res filter.Result
		res, err = f.FilterRequest(ctx, reqAAAA)
		require.NoError(t, err)
		require.NotNil(t, res)

		assert.NotSame(t, cachedRes, res)
	}))
}

func FuzzFilter_FilterRequest(f *testing.F) {
	idx := &filterindex.Typosquatting{
		Domains: []*filterindex.TyposquattingProtectedDomain{{
			Domain:   filtertest.HostTypoProtectedDomain,
			Distance: 4,
		}, {
			Domain:   "another.example",
			Distance: 3,
		}, {
			Domain:   "third.example",
			Distance: 5,
		}},
		Exceptions: []*filterindex.TyposquattingException{{
			Domain: testExceptionDomain,
		}},
	}

	flt := newTestFilter(f, &typosquatting.Config{
		Storage: newTestStorage(idx),
	})

	for _, seed := range []string{
		filtertest.HostTypoProtectedDomain,
		testExceptionDomain,
		filtertest.HostTypoDomain,
		"tset.example",
		"google.com",
		"gogle.com",
		"gooogle.com",
		"a.b",
		"com",
		"x",
		"mail." + filtertest.HostTypoProtectedDomain,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, host string) {
		req := newTestRequest(t, host, dns.TypeA)

		ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
		res, err := flt.FilterRequest(ctx, req)
		require.NoError(t, err)

		if res != nil {
			_ = testutil.RequireTypeAssert[*filter.ResultModifiedRequest](t, res)
		}
	})
}

func BenchmarkFilter_FilterRequest(b *testing.B) {
	// Create a realistic index with many protected domains.
	domains := make([]*filterindex.TyposquattingProtectedDomain, 0, 1000)
	for i := range 1000 {
		domains = append(domains, &filterindex.TyposquattingProtectedDomain{
			Domain:   fmt.Sprintf("test%d.example", i),
			Distance: 3,
		})
	}

	idx := &filterindex.Typosquatting{
		Domains:    domains,
		Exceptions: nil,
	}

	f := newTestFilter(b, &typosquatting.Config{
		Storage: newTestStorage(idx),
	})

	b.Run("correct", func(b *testing.B) {
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

	b.Run("hit_typo", func(b *testing.B) {
		req := newTestRequest(b, "a"+domains[0].Domain, dns.TypeA)
		want := newTestResult(b, req.DNS, filter.RuleText(domains[0].Domain))

		// Warmup to fill the cache.
		ctx := b.Context()
		res, err := f.FilterRequest(ctx, req)
		require.NoError(b, err)
		require.Equal(b, want, res)

		b.ReportAllocs()

		for b.Loop() {
			res, err = f.FilterRequest(ctx, req)
		}

		require.NoError(b, err)

		filtertest.AssertEqualResult(b, want, res)
	})

	b.Run("miss", func(b *testing.B) {
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
	//
	// goos: darwin
	// goarch: arm64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/typosquatting
	// cpu: Apple M4 Pro
	// BenchmarkFilter_FilterRequest/correct-14         	 8395945	       130.9 ns/op	      72 B/op	       2 allocs/op
	// BenchmarkFilter_FilterRequest/hit_typo-14        	 9111565	       132.9 ns/op	      72 B/op	       2 allocs/op
	// BenchmarkFilter_FilterRequest/miss-14            	 8599117	       136.5 ns/op	      72 B/op	       2 allocs/op
}
