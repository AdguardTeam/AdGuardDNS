package composite_test

import (
	"cmp"
	"context"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/custom"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/composite"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/safesearch"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/typosquatting"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/publicsuffix"
)

// Common IP address string representations for tests.
const (
	testIPv4BlockedStr = "192.0.2.1"
	testIPv4PassedStr  = "192.0.2.2"

	testIPv6BlockedStr = "2001:db8::1"
)

// Common IP addresses for tests.
var (
	testIPv4Blocked = netip.MustParseAddr(testIPv4BlockedStr)
	testIPv4Passed  = netip.MustParseAddr(testIPv4PassedStr)

	testIPv6Blocked = netip.MustParseAddr(testIPv6BlockedStr)
)

// Common rules for tests.
const (
	testAllowRuleStr = "@@" + filtertest.RuleBlockStr

	testAllowRule = filter.RuleText(testAllowRuleStr)
)

// newReqData returns data for calling FilterRequest.  The context uses
// [filtertest.Timeout] and [tb.Cleanup] is used for its cancellation.  req uses
// [filtertest.FQDNBlocked], [dns.TypeA], and [dns.ClassINET] for the request
// data.
func newReqData(tb testing.TB) (ctx context.Context, req *filter.Request) {
	tb.Helper()

	return newReqDataWithFQDN(tb, filtertest.FQDNBlocked)
}

// newReqDataWithFQDN is like [newReqData] but allows setting the FQDN.
func newReqDataWithFQDN(tb testing.TB, fqdn string) (ctx context.Context, req *filter.Request) {
	tb.Helper()

	ctx = testutil.ContextWithTimeout(tb, filtertest.Timeout)
	req = &filter.Request{
		DNS:      dnsservertest.NewReq(fqdn, dns.TypeA, dns.ClassINET),
		Messages: agdtest.NewConstructor(tb),
		RemoteIP: filtertest.IPv4Client,
		Host:     agdnet.NormalizeDomain(fqdn),
		QType:    dns.TypeA,
		QClass:   dns.ClassINET,
	}

	return ctx, req
}

// newComposite is a helper for creating composite filters tests.  c may be nil,
// and all zero-value fields in c are replaced with defaults for tests.
func newComposite(tb testing.TB, c *composite.Config) (f *composite.Filter) {
	tb.Helper()

	c = cmp.Or(c, &composite.Config{})
	c.URLFilterRequest = cmp.Or(c.URLFilterRequest, &urlfilter.DNSRequest{})
	c.URLFilterResult = cmp.Or(c.URLFilterResult, &urlfilter.DNSResult{})

	return composite.New(c)
}

func TestFilter_FilterRequest_customWithClientName(t *testing.T) {
	t.Parallel()

	f := newComposite(t, &composite.Config{
		Custom: custom.New(&custom.Config{
			Logger: filtertest.Logger,
			Rules: []filter.RuleText{
				filtertest.RuleBlockForClientName,
			},
		}),
	})

	ctx, req := newReqDataWithFQDN(t, filtertest.FQDNBlockedForClientName)
	res, err := f.FilterRequest(ctx, req)
	require.NoError(t, err)

	assert.Nil(t, res)

	req.ClientName = filtertest.ClientName

	res, err = f.FilterRequest(ctx, req)
	require.NoError(t, err)

	wantRes := &filter.ResultBlocked{
		List: filter.IDCustom,
		Rule: filtertest.RuleBlockForClientName,
	}

	assert.Equal(t, wantRes, res)
}

func TestFilter_FilterRequest_customRuleListWithClientName(t *testing.T) {
	t.Parallel()

	rl := newFromStr(t, filtertest.RuleBlockForClientNameStr, filtertest.RuleListID1)

	f := newComposite(t, &composite.Config{
		CustomRuleLists: []*rulelist.Refreshable{rl},
	})

	ctx, req := newReqDataWithFQDN(t, filtertest.FQDNBlockedForClientName)
	res, err := f.FilterRequest(ctx, req)
	require.NoError(t, err)

	assert.Nil(t, res)

	req.ClientName = filtertest.ClientName

	res, err = f.FilterRequest(ctx, req)
	require.NoError(t, err)

	wantRes := &filter.ResultBlocked{
		List: filtertest.RuleListID1,
		Rule: filtertest.RuleBlockForClientName,
	}

	assert.Equal(t, wantRes, res)
}

func TestFilter_FilterRequest_badfilter(t *testing.T) {
	t.Parallel()

	const (
		blockRule     = filtertest.RuleBlockStr
		badFilterRule = filtertest.RuleBlockStr + "$badfilter"
	)

	rl1 := newFromStr(t, blockRule, filtertest.RuleListID1)
	rl2 := newFromStr(t, badFilterRule, filtertest.RuleListID2)

	testCases := []struct {
		name      string
		wantRes   filter.Result
		ruleLists []*rulelist.Refreshable
	}{{
		name: "block",
		wantRes: &filter.ResultBlocked{
			List: filtertest.RuleListID1,
			Rule: blockRule,
		},
		ruleLists: []*rulelist.Refreshable{rl1},
	}, {
		name:      "badfilter_no_block",
		wantRes:   nil,
		ruleLists: []*rulelist.Refreshable{rl2},
	}, {
		name:      "badfilter_removes_block",
		wantRes:   nil,
		ruleLists: []*rulelist.Refreshable{rl1, rl2},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newComposite(t, &composite.Config{
				RuleLists: tc.ruleLists,
			})

			ctx, req := newReqData(t)
			res, err := f.FilterRequest(ctx, req)
			require.NoError(t, err)

			assert.Equal(t, tc.wantRes, res)
		})
	}
}

// newFromStr is a helper to create a rule-list filter from a rule text and a
// filtering-list ID.
func newFromStr(tb testing.TB, text string, id filter.ID) (rl *rulelist.Refreshable) {
	tb.Helper()

	return rulelist.NewFromString(text, id, "", rulelist.EmptyResultCache{})
}

func TestFilter_FilterRequest_customAllow(t *testing.T) {
	t.Parallel()

	customRL := custom.New(&custom.Config{
		Logger: filtertest.Logger,
		Rules:  []filter.RuleText{testAllowRule},
	})

	want := &filter.ResultAllowed{
		List: filter.IDCustom,
		Rule: testAllowRule,
	}

	t.Run("common_rule_list", func(t *testing.T) {
		t.Parallel()

		blockingRL := newFromStr(t, filtertest.RuleBlockStr, filtertest.RuleListID1)
		f := newComposite(t, &composite.Config{
			Custom:    customRL,
			RuleLists: []*rulelist.Refreshable{blockingRL},
		})

		ctx, req := newReqData(t)
		res, err := f.FilterRequest(ctx, req)
		require.NoError(t, err)

		assert.Equal(t, want, res)
	})

	t.Run("safe_browsing", func(t *testing.T) {
		t.Parallel()

		sb := agdtest.NewFilter()
		sb.OnFilterRequest = func(
			_ context.Context,
			_ *filter.Request,
		) (r filter.Result, err error) {
			return &filter.ResultBlocked{
				List: filtertest.RuleListID1,
			}, nil
		}
		f := newComposite(t, &composite.Config{
			Custom:       customRL,
			SafeBrowsing: sb,
		})

		ctx, req := newReqData(t)
		res, err := f.FilterRequest(ctx, req)
		require.NoError(t, err)

		assert.Equal(t, want, res)
	})

	t.Run("category", func(t *testing.T) {
		t.Parallel()

		domainFilter := filtertest.NewDomainFilter(t, filtertest.HostBlocked)

		f := newComposite(t, &composite.Config{
			Custom:          customRL,
			CategoryFilters: []composite.RequestFilter{domainFilter},
		})

		ctx, req := newReqData(t)
		res, err := f.FilterRequest(ctx, req)
		require.NoError(t, err)

		assert.Equal(t, want, res)
	})
}

func TestFilter_FilterRequest_customBlockDespiteCommonAllow(t *testing.T) {
	t.Parallel()

	allowingRL := newFromStr(t, testAllowRuleStr, filtertest.RuleListID1)

	customRL := custom.New(&custom.Config{
		Logger: filtertest.Logger,
		Rules:  []filter.RuleText{filtertest.RuleBlock},
	})

	f := newComposite(t, &composite.Config{
		Custom:    customRL,
		RuleLists: []*rulelist.Refreshable{allowingRL},
	})

	ctx, req := newReqData(t)
	res, err := f.FilterRequest(ctx, req)
	require.NoError(t, err)

	want := &filter.ResultBlocked{
		List: filter.IDCustom,
		Rule: filtertest.RuleBlockStr,
	}
	assert.Equal(t, want, res)
}

func TestFilter_FilterRequest_dnsrewrite(t *testing.T) {
	t.Parallel()

	const (
		dnsRewriteRuleRefused = filtertest.RuleBlockStr + "$dnsrewrite=REFUSED"
		dnsRewriteRuleCNAME   = filtertest.RuleBlockStr + "$dnsrewrite=" + filtertest.HostCNAME
		dnsRewrite2Rules      = filtertest.RuleBlockStr + "$dnsrewrite=1.2.3.4\n" +
			filtertest.RuleBlockStr + "$dnsrewrite=1.2.3.5"
	)

	var (
		rlNonRewrite    = newFromStr(t, filtertest.RuleBlockStr, filtertest.RuleListID1)
		rlCustomRefused = newCustom(t, dnsRewriteRuleRefused)
		rlCustomCNAME   = newCustom(t, dnsRewriteRuleCNAME)
		rlCustom2Rules  = newCustom(t, dnsRewrite2Rules)
	)

	req := dnsservertest.NewReq(filtertest.FQDNBlocked, dns.TypeA, dns.ClassINET)

	testCases := []struct {
		custom  filter.Custom
		wantRes filter.Result
		name    string
	}{{
		custom: nil,
		wantRes: &filter.ResultBlocked{
			List: filtertest.RuleListID1,
			Rule: filtertest.RuleBlockStr,
		},
		name: "block",
	}, {
		custom: rlCustomRefused,
		wantRes: &filter.ResultModifiedResponse{
			Msg:  dnsservertest.NewResp(dns.RcodeRefused, req),
			List: filter.IDCustom,
			Rule: dnsRewriteRuleRefused,
		},
		name: "dnsrewrite_block",
	}, {
		custom: rlCustomCNAME,
		wantRes: &filter.ResultModifiedRequest{
			Msg:  dnsservertest.NewReq(filtertest.FQDNCname, dns.TypeA, dns.ClassINET),
			List: filter.IDCustom,
			Rule: dnsRewriteRuleCNAME,
		},
		name: "dnsrewrite_cname",
	}, {
		custom: rlCustom2Rules,
		wantRes: &filter.ResultModifiedResponse{
			Msg: dnsservertest.NewResp(dns.RcodeSuccess, req, dnsservertest.SectionAnswer{
				dnsservertest.NewA(
					filtertest.FQDNBlocked,
					agdtest.FilteredResponseTTLSec,
					netip.MustParseAddr("1.2.3.4"),
				),
				dnsservertest.NewA(
					filtertest.FQDNBlocked,
					agdtest.FilteredResponseTTLSec,
					netip.MustParseAddr("1.2.3.5"),
				),
			}),
			List: filter.IDCustom,
			Rule: "",
		},
		name: "dnsrewrite_answers",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newComposite(t, &composite.Config{
				Custom:    tc.custom,
				RuleLists: []*rulelist.Refreshable{rlNonRewrite},
			})

			ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
			res, err := f.FilterRequest(ctx, &filter.Request{
				DNS:      req,
				Messages: agdtest.NewConstructor(t),
				Host:     filtertest.HostBlocked,
				QType:    req.Question[0].Qtype,
			})

			require.NoError(t, err)

			filtertest.AssertEqualResult(t, tc.wantRes, res)
		})
	}
}

func TestFilter_FilterRequest_dnsrewriteQType(t *testing.T) {
	t.Parallel()

	const (
		dnsRewriteRuleTXT = filtertest.RuleBlockStr + "$dnsrewrite=NOERROR;TXT;abcdefg"
		dnsRewriteRuleSOA = filtertest.RuleBlockStr + "$dnsrewrite=NOERROR;SOA;ns1." +
			filtertest.FQDNBlocked + " hostmaster." + filtertest.FQDNBlocked +
			" 1 3600 1800 604800 86400"

		dnsRewriteTypedRules = dnsRewriteRuleTXT + "\n" + dnsRewriteRuleSOA
	)

	txtReq := dnsservertest.NewReq(filtertest.FQDNBlocked, dns.TypeTXT, dns.ClassINET)
	soaReq := dnsservertest.NewReq(filtertest.FQDNBlocked, dns.TypeSOA, dns.ClassINET)

	testCases := []struct {
		req     *dns.Msg
		wantRes filter.Result
		name    string
	}{{
		req: txtReq,
		wantRes: &filter.ResultModifiedResponse{
			Msg: dnsservertest.NewResp(dns.RcodeSuccess, txtReq, dnsservertest.SectionAnswer{
				dnsservertest.NewTXT(
					filtertest.FQDNBlocked,
					agdtest.FilteredResponseTTLSec,
					"abcdefg",
				),
			}),
			List: filter.IDCustom,
			Rule: "",
		},
		name: "dnsrewrite_txt",
	}, {
		req: soaReq,
		wantRes: &filter.ResultModifiedResponse{
			Msg:  dnsservertest.NewResp(dns.RcodeSuccess, soaReq),
			List: filter.IDCustom,
		},
		name: "dnsrewrite_soa",
	}}

	f := newComposite(t, &composite.Config{
		Custom:    newCustom(t, dnsRewriteTypedRules),
		RuleLists: []*rulelist.Refreshable{},
	})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
			res, err := f.FilterRequest(ctx, &filter.Request{
				DNS:      tc.req,
				Messages: agdtest.NewConstructor(t),
				Host:     filtertest.HostBlocked,
				QType:    tc.req.Question[0].Qtype,
			})
			require.NoError(t, err)

			filtertest.AssertEqualResult(t, tc.wantRes, res)
		})
	}
}

// newCustom is a helper to create a custom filter from a rule text.
func newCustom(tb testing.TB, text string) (f *custom.Filter) {
	tb.Helper()

	return custom.New(&custom.Config{
		Logger: filtertest.Logger,
		Rules: []filter.RuleText{
			filter.RuleText(text),
		},
	})
}

func TestFilter_FilterRequest_hostsRules(t *testing.T) {
	t.Parallel()

	const (
		reqHost4 = "www.example.com"
		reqHost6 = "www.example.net"
	)

	const (
		blockRule4 = "127.0.0.1 www.example.com"
		blockRule6 = "::1 www.example.net"
		rules      = blockRule4 + "\n" + blockRule6
	)

	rl := newFromStr(t, rules, filtertest.RuleListID1)
	f := newComposite(t, &composite.Config{
		RuleLists: []*rulelist.Refreshable{rl},
	})

	resBlocked4 := &filter.ResultBlocked{
		List: filtertest.RuleListID1,
		Rule: blockRule4,
	}

	resBlocked6 := &filter.ResultBlocked{
		List: filtertest.RuleListID1,
		Rule: blockRule6,
	}

	testCases := []struct {
		wantRes filter.Result
		name    string
		reqHost string
		reqType dnsmsg.RRType
	}{{
		wantRes: resBlocked4,
		name:    "a",
		reqHost: reqHost4,
		reqType: dns.TypeA,
	}, {
		wantRes: resBlocked6,
		name:    "aaaa",
		reqHost: reqHost6,
		reqType: dns.TypeAAAA,
	}, {
		wantRes: resBlocked6,
		name:    "a_with_ipv6_rule",
		reqHost: reqHost6,
		reqType: dns.TypeA,
	}, {
		wantRes: resBlocked4,
		name:    "aaaa_with_ipv4_rule",
		reqHost: reqHost4,
		reqType: dns.TypeAAAA,
	}, {
		wantRes: resBlocked4,
		name:    "mx",
		reqHost: reqHost4,
		reqType: dns.TypeMX,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &dns.Msg{
				Question: []dns.Question{{
					Name:   dns.Fqdn(tc.reqHost),
					Qtype:  tc.reqType,
					Qclass: dns.ClassINET,
				}},
			}

			ctx := context.Background()
			fltReq := &filter.Request{
				DNS:      req,
				Messages: agdtest.NewConstructor(t),
				Host:     tc.reqHost,
				QType:    tc.reqType,
			}

			res, fltErr := f.FilterRequest(ctx, fltReq)
			require.NoError(t, fltErr)

			assert.Equal(t, tc.wantRes, res)
			assert.Equal(t, tc.wantRes, res)
		})
	}
}

func TestFilter_FilterRequest_safeSearch(t *testing.T) {
	t.Parallel()

	const rewriteRule = filtertest.RuleSafeSearchGeneralIPv4Str + "\n"
	cachePath, srvURL := filtertest.PrepareRefreshable(t, nil, rewriteRule, http.StatusOK)

	const fltListID = filter.IDGeneralSafeSearch

	gen, err := safesearch.New(
		&safesearch.Config{
			Refreshable: &refreshable.Config{
				Logger:    filtertest.Logger,
				URL:       srvURL,
				ID:        fltListID,
				CachePath: cachePath,
				Staleness: filtertest.Staleness,
				Timeout:   filtertest.Timeout,
				MaxSize:   filtertest.FilterMaxSize,
			},
			CacheTTL: 1 * time.Minute,
		},
		rulelist.NewResultCache(filtertest.CacheCount, true),
	)
	require.NoError(t, err)

	err = gen.Refresh(testutil.ContextWithTimeout(t, filtertest.Timeout), false)
	require.NoError(t, err)

	f := newComposite(t, &composite.Config{
		GeneralSafeSearch: gen,
	})

	ctx, req := newReqDataWithFQDN(t, filtertest.FQDNSafeSearchGeneralIPv4)
	res, err := f.FilterRequest(ctx, req)
	require.NoError(t, err)

	wantResp := dnsservertest.NewResp(dns.RcodeSuccess, req.DNS, dnsservertest.SectionAnswer{
		dnsservertest.NewA(
			filtertest.FQDNSafeSearchGeneralIPv4,
			agdtest.FilteredResponseTTLSec,
			filtertest.IPv4SafeSearchRepl,
		),
	})
	want := &filter.ResultModifiedResponse{
		Msg:  wantResp,
		List: fltListID,
		Rule: filtertest.HostSafeSearchGeneralIPv4,
	}
	assert.Equal(t, want, res)
}

func TestFilter_FilterRequest_services(t *testing.T) {
	t.Parallel()

	svcRL := rulelist.NewImmutable(
		[]byte(filtertest.RuleBlockStr),
		filter.IDBlockedService,
		filtertest.BlockedServiceID1,
		rulelist.EmptyResultCache{},
	)

	f := newComposite(t, &composite.Config{
		ServiceLists: []*rulelist.Immutable{svcRL},
	})

	ctx, req := newReqData(t)
	res, err := f.FilterRequest(ctx, req)
	require.NoError(t, err)

	want := &filter.ResultBlocked{
		List: filter.IDBlockedService,
		Rule: filter.RuleText(filtertest.BlockedServiceID1),
	}
	assert.Equal(t, want, res)
}

func TestFilter_FilterRequest_domainFilters(t *testing.T) {
	t.Parallel()

	const (
		fltRespTTL = agdtest.FilteredResponseTTLSec
		testDomain = filtertest.HostBlocked
	)

	domainFilter := filtertest.NewDomainFilter(t, testDomain)
	f := newComposite(t, &composite.Config{
		CategoryFilters: []composite.RequestFilter{domainFilter},
	})

	ctx, req := newReqData(t)
	res, err := f.FilterRequest(ctx, req)
	require.NoError(t, err)

	want := &filter.ResultBlocked{
		List: filter.IDCategory,
		Rule: filter.RuleText(filtertest.CategoryIDStr),
	}
	assert.Equal(t, want, res)
}

func TestFilter_FilterRequest_typosquatting(t *testing.T) {
	t.Parallel()

	cloner := agdtest.NewCloner()
	replCons, err := filter.NewReplacedResultConstructor(&filter.ReplacedResultConstructorConfig{
		Cloner:      cloner,
		Replacement: filtertest.HostDangerousRepl,
	})
	require.NoError(t, err)

	s := &agdtest.FilterIndexStorage{
		OnTyposquatting: func(_ context.Context) (idx *filterindex.Typosquatting, err error) {
			domains := []*filterindex.TyposquattingProtectedDomain{{
				Domain:   filtertest.HostTypoProtectedDomain,
				Distance: 1,
			}}

			return &filterindex.Typosquatting{
				Domains: domains,
			}, nil
		},
	}

	cachePath := filepath.Join(t.TempDir(), "typosquatting.json")

	ts := typosquatting.New(&typosquatting.Config{
		Cloner:                    cloner,
		Logger:                    filtertest.Logger,
		ReplacedResultConstructor: replCons,
		CacheManager:              agdcache.EmptyManager{},
		Clock:                     timeutil.SystemClock{},
		ErrColl:                   agdtest.NewErrorCollector(),
		Metrics:                   filter.EmptyMetrics{},
		PublicSuffixList:          publicsuffix.List,
		Storage:                   s,
		CachePath:                 cachePath,
		ResultListID:              filter.IDTyposquatting,
		Staleness:                 filtertest.Staleness,
		CacheCount:                filtertest.CacheCount,
	})

	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
	err = ts.RefreshInitial(ctx)
	require.NoError(t, err)

	f := newComposite(t, &composite.Config{
		Typosquatting: ts,
	})

	ctx, req := newReqDataWithFQDN(t, filtertest.FQDNTypoDomain)
	res, err := f.FilterRequest(ctx, req)
	require.NoError(t, err)

	wantReq := dnsservertest.NewReq(filtertest.FQDNDangerousRepl, dns.TypeA, dns.ClassINET)
	want := &filter.ResultModifiedRequest{
		Msg:  wantReq,
		List: filter.IDTyposquatting,
		Rule: filtertest.HostTypoProtectedDomain,
	}

	filtertest.AssertEqualResult(t, want, res)
}

func TestFilter_FilterResponse(t *testing.T) {
	t.Parallel()

	const blockRules = filtertest.HostBlocked + "\n" +
		testIPv4BlockedStr + "\n" +
		testIPv6BlockedStr + "\n"

	blockingRL := newFromStr(t, blockRules, filtertest.RuleListID1)
	f := newComposite(t, &composite.Config{
		RuleLists: []*rulelist.Refreshable{blockingRL},
	})

	const ttl = agdtest.FilteredResponseTTLSec

	testCases := []struct {
		want    filter.Result
		name    string
		reqFQDN string
		respAns dnsservertest.SectionAnswer
	}{{
		want:    nil,
		name:    "pass",
		reqFQDN: filtertest.FQDN,
		respAns: dnsservertest.SectionAnswer{
			dnsservertest.NewA(filtertest.FQDN, ttl, testIPv4Passed),
		},
	}, {
		want: &filter.ResultBlocked{
			List: filtertest.RuleListID1,
			Rule: filtertest.HostBlocked,
		},
		name:    "cname",
		reqFQDN: filtertest.FQDNCname,
		respAns: dnsservertest.SectionAnswer{
			dnsservertest.NewCNAME(filtertest.FQDNCname, ttl, filtertest.FQDNBlocked),
			dnsservertest.NewA(filtertest.FQDNBlocked, ttl, testIPv4Blocked),
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, req := newReqDataWithFQDN(t, tc.reqFQDN)
			res, err := f.FilterResponse(ctx, &filter.Response{
				DNS:      dnsservertest.NewResp(dns.RcodeSuccess, req.DNS, tc.respAns),
				RemoteIP: filtertest.IPv4Client,
			})
			require.NoError(t, err)

			assert.Equal(t, tc.want, res)
		})
	}
}

func TestFilter_FilterResponse_blocked(t *testing.T) {
	t.Parallel()

	const blockRules = filtertest.HostBlocked + "\n" +
		testIPv4BlockedStr + "\n" +
		testIPv6BlockedStr + "\n"

	resBlocked4 := &filter.ResultBlocked{
		List: filtertest.RuleListID1,
		Rule: testIPv4BlockedStr,
	}

	resBlocked6 := &filter.ResultBlocked{
		List: filtertest.RuleListID1,
		Rule: testIPv6BlockedStr,
	}

	blockingRL := newFromStr(t, blockRules, filtertest.RuleListID1)
	f := newComposite(t, &composite.Config{
		RuleLists: []*rulelist.Refreshable{blockingRL},
	})

	const ttl = agdtest.FilteredResponseTTLSec

	testCases := []struct {
		want    filter.Result
		name    string
		respAns dnsservertest.SectionAnswer
		qType   dnsmsg.RRType
	}{{
		want: resBlocked4,
		name: "ipv4",
		respAns: dnsservertest.SectionAnswer{
			dnsservertest.NewA(filtertest.FQDNBlocked, ttl, testIPv4Blocked),
		},
		qType: dns.TypeA,
	}, {
		want: resBlocked6,
		name: "ipv6",
		respAns: dnsservertest.SectionAnswer{
			dnsservertest.NewAAAA(filtertest.FQDNBlocked, ttl, testIPv6Blocked),
		},
		qType: dns.TypeAAAA,
	}, {
		want: resBlocked4,
		name: "ipv4hint",
		respAns: dnsservertest.SectionAnswer{dnsservertest.NewHTTPS(
			filtertest.FQDNBlocked,
			ttl,
			[]netip.Addr{testIPv4Blocked},
			[]netip.Addr{},
		)},
		qType: dns.TypeHTTPS,
	}, {
		want: resBlocked6,
		name: "ipv6hint",
		respAns: dnsservertest.SectionAnswer{dnsservertest.NewHTTPS(
			filtertest.FQDNBlocked,
			ttl,
			[]netip.Addr{},
			[]netip.Addr{testIPv6Blocked},
		)},
		qType: dns.TypeHTTPS,
	}, {
		want: resBlocked4,
		name: "ipv4_ipv6_hints",
		respAns: dnsservertest.SectionAnswer{dnsservertest.NewHTTPS(
			filtertest.FQDNBlocked,
			ttl,
			[]netip.Addr{testIPv4Blocked},
			[]netip.Addr{testIPv6Blocked},
		)},
		qType: dns.TypeHTTPS,
	}, {
		want: nil,
		name: "pass_hints",
		respAns: dnsservertest.SectionAnswer{dnsservertest.NewHTTPS(
			filtertest.FQDNBlocked,
			ttl,
			[]netip.Addr{testIPv4Passed},
			[]netip.Addr{},
		)},
		qType: dns.TypeHTTPS,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, req := newReqDataWithFQDN(t, filtertest.FQDNBlocked)
			req.DNS.Question[0].Qtype = tc.qType

			res, err := f.FilterResponse(ctx, &filter.Response{
				DNS:      dnsservertest.NewResp(dns.RcodeSuccess, req.DNS, tc.respAns),
				RemoteIP: filtertest.IPv4Client,
			})
			require.NoError(t, err)

			assert.Equal(t, tc.want, res)
		})
	}
}

func TestFilter_FilterResponse_customRuleList(t *testing.T) {
	t.Parallel()

	rl := newFromStr(t, testIPv4BlockedStr, filtertest.RuleListID1)

	f := newComposite(t, &composite.Config{
		CustomRuleLists: []*rulelist.Refreshable{rl},
	})

	ctx, req := newReqDataWithFQDN(t, filtertest.FQDN)
	respAns := dnsservertest.SectionAnswer{
		dnsservertest.NewA(filtertest.FQDN, agdtest.FilteredResponseTTLSec, testIPv4Blocked),
	}

	res, err := f.FilterResponse(ctx, &filter.Response{
		DNS:      dnsservertest.NewResp(dns.RcodeSuccess, req.DNS, respAns),
		RemoteIP: filtertest.IPv4Client,
	})
	require.NoError(t, err)

	wantRes := &filter.ResultBlocked{
		List: filtertest.RuleListID1,
		Rule: testIPv4BlockedStr,
	}

	assert.Equal(t, wantRes, res)
}
