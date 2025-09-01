package composite_test

import (
	"cmp"
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/custom"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/composite"
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
	f := newComposite(t, &composite.Config{
		Custom: custom.New(&custom.Config{
			Logger: slogutil.NewDiscardLogger(),
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

func TestFilter_FilterRequest_badfilter(t *testing.T) {
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
	const allowRule = "@@" + filtertest.RuleBlock

	blockingRL := newFromStr(t, filtertest.RuleBlockStr, filtertest.RuleListID1)
	customRL := custom.New(&custom.Config{
		Logger: slogutil.NewDiscardLogger(),
		Rules:  []filter.RuleText{allowRule},
	})

	f := newComposite(t, &composite.Config{
		Custom:    customRL,
		RuleLists: []*rulelist.Refreshable{blockingRL},
	})

	ctx, req := newReqData(t)
	res, err := f.FilterRequest(ctx, req)
	require.NoError(t, err)

	want := &filter.ResultAllowed{
		List: filter.IDCustom,
		Rule: allowRule,
	}
	assert.Equal(t, want, res)
}

func TestFilter_FilterRequest_dnsrewrite(t *testing.T) {
	const (
		blockRule             = filtertest.RuleBlockStr
		dnsRewriteRuleRefused = filtertest.RuleBlockStr + "$dnsrewrite=REFUSED"
		dnsRewriteRuleCname   = filtertest.RuleBlockStr + "$dnsrewrite=new-cname.example"
		dnsRewrite2Rules      = filtertest.RuleBlockStr + "$dnsrewrite=1.2.3.4\n" +
			filtertest.RuleBlockStr + "$dnsrewrite=1.2.3.5"
		dnsRewriteRuleTXT = filtertest.RuleBlockStr + "$dnsrewrite=NOERROR;TXT;abcdefg"
		dnsRewriteRuleSOA = filtertest.RuleBlockStr + "$dnsrewrite=NOERROR;SOA;ns1." +
			filtertest.FQDNBlocked + " hostmaster." + filtertest.FQDNBlocked +
			" 1 3600 1800 604800 86400"
		dnsRewriteTypedRules = dnsRewriteRuleTXT + "\n" + dnsRewriteRuleSOA
	)

	var (
		rlNonRewrite    = newFromStr(t, blockRule, filtertest.RuleListID1)
		rlCustomRefused = newCustom(t, dnsRewriteRuleRefused)
		rlCustomCname   = newCustom(t, dnsRewriteRuleCname)
		rlCustom2Rules  = newCustom(t, dnsRewrite2Rules)
		rlCustomTyped   = newCustom(t, dnsRewriteTypedRules)
	)

	req := dnsservertest.NewReq(filtertest.FQDNBlocked, dns.TypeA, dns.ClassINET)

	// Create a CNAME-modified request.
	modifiedReq := dnsmsg.Clone(req)
	modifiedReq.Question[0].Name = "new-cname.example."

	txtReq := dnsmsg.Clone(req)
	txtReq.Question[0].Qtype = dns.TypeTXT

	soaReq := dnsmsg.Clone(req)
	soaReq.Question[0].Qtype = dns.TypeSOA

	testCases := []struct {
		custom    filter.Custom
		req       *dns.Msg
		wantRes   filter.Result
		name      string
		ruleLists []*rulelist.Refreshable
	}{{
		custom: nil,
		req:    req,
		wantRes: &filter.ResultBlocked{
			List: filtertest.RuleListID1,
			Rule: blockRule,
		},
		name:      "block",
		ruleLists: []*rulelist.Refreshable{rlNonRewrite},
	}, {
		custom: nil,
		req:    req,
		wantRes: &filter.ResultBlocked{
			List: filtertest.RuleListID1,
			Rule: blockRule,
		},
		name:      "dnsrewrite_no_effect",
		ruleLists: []*rulelist.Refreshable{rlNonRewrite},
	}, {
		custom: rlCustomRefused,
		req:    req,
		wantRes: &filter.ResultModifiedResponse{
			Msg:  dnsservertest.NewResp(dns.RcodeRefused, req),
			List: filter.IDCustom,
			Rule: dnsRewriteRuleRefused,
		},
		name:      "dnsrewrite_block",
		ruleLists: []*rulelist.Refreshable{rlNonRewrite},
	}, {
		custom: rlCustomCname,
		req:    req,
		wantRes: &filter.ResultModifiedRequest{
			Msg:  modifiedReq,
			List: filter.IDCustom,
			Rule: dnsRewriteRuleCname,
		},
		name:      "dnsrewrite_cname",
		ruleLists: []*rulelist.Refreshable{rlNonRewrite},
	}, {
		custom: rlCustom2Rules,
		req:    req,
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
		name:      "dnsrewrite_answers",
		ruleLists: []*rulelist.Refreshable{rlNonRewrite},
	}, {
		custom: rlCustomTyped,
		req:    txtReq,
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
		name:      "dnsrewrite_txt",
		ruleLists: []*rulelist.Refreshable{},
	}, {
		custom: rlCustomTyped,
		req:    soaReq,
		wantRes: &filter.ResultModifiedResponse{
			Msg:  dnsservertest.NewResp(dns.RcodeSuccess, soaReq),
			List: filter.IDCustom,
		},
		name:      "dnsrewrite_soa",
		ruleLists: []*rulelist.Refreshable{},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newComposite(t, &composite.Config{
				Custom:    tc.custom,
				RuleLists: tc.ruleLists,
			})

			ctx := context.Background()
			res, fltErr := f.FilterRequest(ctx, &filter.Request{
				DNS:      tc.req,
				Messages: agdtest.NewConstructor(t),
				Host:     filtertest.HostBlocked,
				QType:    tc.req.Question[0].Qtype,
			})

			require.NoError(t, fltErr)

			filtertest.AssertEqualResult(t, tc.wantRes, res)
		})
	}
}

// newCustom is a helper to create a custom filter from a rule text.
func newCustom(tb testing.TB, text string) (f *custom.Filter) {
	tb.Helper()

	return custom.New(&custom.Config{
		Logger: slogutil.NewDiscardLogger(),
		Rules: []filter.RuleText{
			filter.RuleText(text),
		},
	})
}

func TestFilter_FilterRequest_hostsRules(t *testing.T) {
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
	const rewriteRule = filtertest.RuleSafeSearchGeneralIPv4Str + "\n"
	cachePath, srvURL := filtertest.PrepareRefreshable(t, nil, rewriteRule, http.StatusOK)

	const fltListID = filter.IDGeneralSafeSearch

	gen, err := safesearch.New(
		&safesearch.Config{
			Refreshable: &refreshable.Config{
				Logger:    slogutil.NewDiscardLogger(),
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

func TestFilter_FilterResponse(t *testing.T) {
	const cnameReqFQDN = "sub." + filtertest.FQDNBlocked

	const (
		passedIPv4Str  = "1.1.1.1"
		blockedIPv4Str = "1.2.3.4"
		blockedIPv6Str = "1234::cdef"
		blockRules     = filtertest.HostBlocked + "\n" +
			blockedIPv4Str + "\n" +
			blockedIPv6Str + "\n"
	)

	var (
		passedIPv4  = netip.MustParseAddr(passedIPv4Str)
		blockedIPv4 = netip.MustParseAddr(blockedIPv4Str)
		blockedIPv6 = netip.MustParseAddr(blockedIPv6Str)
	)

	blockingRL := newFromStr(t, blockRules, filtertest.RuleListID1)
	f := newComposite(t, &composite.Config{
		RuleLists: []*rulelist.Refreshable{blockingRL},
	})

	const ttl = agdtest.FilteredResponseTTLSec

	testCases := []struct {
		name     string
		reqFQDN  string
		wantRule filter.RuleText
		respAns  dnsservertest.SectionAnswer
		qType    dnsmsg.RRType
	}{{
		name:     "pass",
		reqFQDN:  filtertest.FQDN,
		wantRule: "",
		respAns: dnsservertest.SectionAnswer{
			dnsservertest.NewA(filtertest.FQDN, ttl, passedIPv4),
		},
		qType: dns.TypeA,
	}, {
		name:     "cname",
		reqFQDN:  cnameReqFQDN,
		wantRule: filtertest.HostBlocked,
		respAns: dnsservertest.SectionAnswer{
			dnsservertest.NewCNAME(cnameReqFQDN, ttl, filtertest.FQDNBlocked),
			dnsservertest.NewA(filtertest.FQDNBlocked, ttl, netip.MustParseAddr("1.2.3.4")),
		},
		qType: dns.TypeA,
	}, {
		name:     "ipv4",
		reqFQDN:  filtertest.FQDNBlocked,
		wantRule: blockedIPv4Str,
		respAns: dnsservertest.SectionAnswer{
			dnsservertest.NewA(filtertest.FQDNBlocked, ttl, blockedIPv4),
		},
		qType: dns.TypeA,
	}, {
		name:     "ipv6",
		reqFQDN:  filtertest.FQDNBlocked,
		wantRule: blockedIPv6Str,
		respAns: dnsservertest.SectionAnswer{
			dnsservertest.NewAAAA(filtertest.FQDNBlocked, ttl, blockedIPv6),
		},
		qType: dns.TypeAAAA,
	}, {
		name:     "ipv4hint",
		reqFQDN:  filtertest.FQDNBlocked,
		wantRule: blockedIPv4Str,
		respAns: dnsservertest.SectionAnswer{dnsservertest.NewHTTPS(
			filtertest.FQDNBlocked,
			ttl,
			[]netip.Addr{blockedIPv4},
			[]netip.Addr{},
		)},
		qType: dns.TypeHTTPS,
	}, {
		name:     "ipv6hint",
		reqFQDN:  filtertest.FQDNBlocked,
		wantRule: blockedIPv6Str,
		respAns: dnsservertest.SectionAnswer{dnsservertest.NewHTTPS(
			filtertest.FQDNBlocked,
			ttl,
			[]netip.Addr{},
			[]netip.Addr{blockedIPv6},
		)},
		qType: dns.TypeHTTPS,
	}, {
		name:     "ipv4_ipv6_hints",
		reqFQDN:  filtertest.FQDNBlocked,
		wantRule: blockedIPv4Str,
		respAns: dnsservertest.SectionAnswer{dnsservertest.NewHTTPS(
			filtertest.FQDNBlocked,
			ttl,
			[]netip.Addr{blockedIPv4},
			[]netip.Addr{blockedIPv6},
		)},
		qType: dns.TypeHTTPS,
	}, {
		name:     "pass_hints",
		reqFQDN:  filtertest.FQDNBlocked,
		wantRule: "",
		respAns: dnsservertest.SectionAnswer{dnsservertest.NewHTTPS(
			filtertest.FQDNBlocked,
			ttl,
			[]netip.Addr{passedIPv4},
			[]netip.Addr{},
		)},
		qType: dns.TypeHTTPS,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, req := newReqDataWithFQDN(t, tc.reqFQDN)
			req.DNS.Question[0].Qtype = tc.qType

			res, err := f.FilterResponse(ctx, &filter.Response{
				DNS:      dnsservertest.NewResp(dns.RcodeSuccess, req.DNS, tc.respAns),
				RemoteIP: filtertest.IPv4Client,
			})
			require.NoError(t, err)

			if tc.wantRule == "" {
				assert.Nil(t, res)

				return
			}

			want := &filter.ResultBlocked{
				List: filtertest.RuleListID1,
				Rule: tc.wantRule,
			}
			assert.Equal(t, want, res)
		})
	}
}
