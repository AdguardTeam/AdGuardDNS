package composite_test

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/composite"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/safesearch"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// Common filter list IDs for tests.
const (
	testFltListID1 agd.FilterListID = "fl1"
	testFltListID2 agd.FilterListID = "fl2"
)

// newFromStr is a helper to create a rule-list filter from a rule text and a
// filtering-list ID.
func newFromStr(tb testing.TB, text string, id agd.FilterListID) (rl *rulelist.Refreshable) {
	tb.Helper()

	rl, err := rulelist.NewFromString(text, id, "", 0, false)
	require.NoError(tb, err)

	return rl
}

// newImmutable is a helper to create an immutable rule-list filter from a rule
// text and a filtering-list ID.
func newImmutable(tb testing.TB, text string, id agd.FilterListID) (rl *rulelist.Immutable) {
	tb.Helper()

	rl, err := rulelist.NewImmutable(text, id, "", 0, false)
	require.NoError(tb, err)

	return rl
}

// newReqData returns data for calling FilterRequest.  The context uses
// [filtertest.Timeout] and [tb.Cleanup] is used for its cancellation.  Both req
// and ri use [filtertest.ReqFQDN], [dns.TypeA], and [dns.ClassINET] for the
// request data.
func newReqData(tb testing.TB) (ctx context.Context, req *dns.Msg, ri *agd.RequestInfo) {
	ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
	tb.Cleanup(cancel)

	req = dnsservertest.NewReq(filtertest.ReqFQDN, dns.TypeA, dns.ClassINET)
	ri = &agd.RequestInfo{
		Messages: agdtest.NewConstructor(),
		Host:     filtertest.ReqHost,
		QType:    dns.TypeA,
		QClass:   dns.ClassINET,
	}

	return ctx, req, ri
}

func TestFilter_nil(t *testing.T) {
	testCases := []struct {
		flt  *composite.Filter
		name string
	}{{
		flt:  nil,
		name: "nil",
	}, {
		flt:  composite.New(nil),
		name: "config_nil",
	}, {
		flt:  composite.New(&composite.Config{}),
		name: "config_empty",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, req, ri := newReqData(t)
			res, err := tc.flt.FilterRequest(ctx, req, ri)
			assert.NoError(t, err)
			assert.Nil(t, res)

			resp := dnsservertest.NewResp(dns.RcodeSuccess, req)
			res, err = tc.flt.FilterResponse(ctx, resp, ri)
			assert.NoError(t, err)
			assert.Nil(t, res)
		})
	}
}

func TestFilter_FilterRequest_badfilter(t *testing.T) {
	const (
		blockRule     = filtertest.BlockRule
		badFilterRule = filtertest.BlockRule + "$badfilter"
	)

	rl1 := newFromStr(t, blockRule, testFltListID1)
	rl2 := newFromStr(t, badFilterRule, testFltListID2)

	testCases := []struct {
		name      string
		wantRes   internal.Result
		ruleLists []*rulelist.Refreshable
	}{{
		name: "block",
		wantRes: &internal.ResultBlocked{
			List: testFltListID1,
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
			f := composite.New(&composite.Config{
				RuleLists: tc.ruleLists,
			})

			ctx, req, ri := newReqData(t)
			res, err := f.FilterRequest(ctx, req, ri)
			require.NoError(t, err)

			assert.Equal(t, tc.wantRes, res)
		})
	}
}

func TestFilter_FilterRequest_customAllow(t *testing.T) {
	const allowRule = "@@" + filtertest.BlockRule

	blockingRL := newFromStr(t, filtertest.BlockRule, testFltListID1)
	customRL := newImmutable(t, allowRule, agd.FilterListIDCustom)

	f := composite.New(&composite.Config{
		Custom:    customRL,
		RuleLists: []*rulelist.Refreshable{blockingRL},
	})

	ctx, req, ri := newReqData(t)
	res, err := f.FilterRequest(ctx, req, ri)
	require.NoError(t, err)

	want := &internal.ResultAllowed{
		List: agd.FilterListIDCustom,
		Rule: allowRule,
	}
	assert.Equal(t, want, res)
}

func TestFilter_FilterRequest_dnsrewrite(t *testing.T) {
	const (
		blockRule             = filtertest.BlockRule
		dnsRewriteRuleRefused = filtertest.BlockRule + "$dnsrewrite=REFUSED"
		dnsRewriteRuleCname   = filtertest.BlockRule + "$dnsrewrite=new-cname.example"
		dnsRewrite2Rules      = filtertest.BlockRule + "$dnsrewrite=1.2.3.4\n" +
			filtertest.BlockRule + "$dnsrewrite=1.2.3.5"
		dnsRewriteRuleTXT = filtertest.BlockRule + "$dnsrewrite=NOERROR;TXT;abcdefg"
	)

	var (
		rlNonRewrite     = newFromStr(t, blockRule, testFltListID1)
		rlRewriteIgnored = newFromStr(t, dnsRewriteRuleRefused, testFltListID2)
		rlCustomRefused  = newImmutable(t, dnsRewriteRuleRefused, agd.FilterListIDCustom)
		rlCustomCname    = newImmutable(t, dnsRewriteRuleCname, agd.FilterListIDCustom)
		rlCustom2Rules   = newImmutable(t, dnsRewrite2Rules, agd.FilterListIDCustom)
	)

	req := dnsservertest.NewReq(filtertest.ReqFQDN, dns.TypeA, dns.ClassINET)

	// Create a CNAME-modified request.
	modifiedReq := dnsmsg.Clone(req)
	modifiedReq.Question[0].Name = "new-cname.example."

	testCases := []struct {
		custom    *rulelist.Immutable
		wantRes   internal.Result
		name      string
		ruleLists []*rulelist.Refreshable
	}{{
		custom:    nil,
		wantRes:   &internal.ResultBlocked{List: testFltListID1, Rule: blockRule},
		name:      "block",
		ruleLists: []*rulelist.Refreshable{rlNonRewrite},
	}, {
		custom:    nil,
		wantRes:   &internal.ResultBlocked{List: testFltListID1, Rule: blockRule},
		name:      "dnsrewrite_no_effect",
		ruleLists: []*rulelist.Refreshable{rlNonRewrite, rlRewriteIgnored},
	}, {
		custom: rlCustomRefused,
		wantRes: &internal.ResultModified{
			Msg:  dnsservertest.NewResp(dns.RcodeRefused, req),
			List: agd.FilterListIDCustom,
			Rule: dnsRewriteRuleRefused,
		},
		name:      "dnsrewrite_block",
		ruleLists: []*rulelist.Refreshable{rlNonRewrite, rlRewriteIgnored},
	}, {
		custom: rlCustomCname,
		wantRes: &internal.ResultModified{
			Msg:  modifiedReq,
			List: agd.FilterListIDCustom,
			Rule: dnsRewriteRuleCname,
		},
		name:      "dnsrewrite_cname",
		ruleLists: []*rulelist.Refreshable{rlNonRewrite, rlRewriteIgnored},
	}, {
		custom: rlCustom2Rules,
		wantRes: &internal.ResultModified{
			Msg: dnsservertest.NewResp(dns.RcodeSuccess, req, dnsservertest.SectionAnswer{
				dnsservertest.NewA(
					filtertest.ReqFQDN,
					agdtest.FilteredResponseTTLSec,
					net.IP{1, 2, 3, 4},
				),
				dnsservertest.NewA(
					filtertest.ReqFQDN,
					agdtest.FilteredResponseTTLSec,
					net.IP{1, 2, 3, 5},
				),
			}),
			List: agd.FilterListIDCustom,
			Rule: "",
		},
		name:      "dnsrewrite_answers",
		ruleLists: []*rulelist.Refreshable{rlNonRewrite, rlRewriteIgnored},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := composite.New(&composite.Config{
				Custom:    tc.custom,
				RuleLists: tc.ruleLists,
			})

			ctx := context.Background()
			ri := &agd.RequestInfo{
				Messages: agdtest.NewConstructor(),
				Host:     filtertest.ReqHost,
				QType:    dns.TypeA,
			}

			res, fltErr := f.FilterRequest(ctx, req, ri)
			require.NoError(t, fltErr)

			assert.Equal(t, tc.wantRes, res)
		})
	}
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

	rl := newFromStr(t, rules, testFltListID1)
	f := composite.New(&composite.Config{
		RuleLists: []*rulelist.Refreshable{rl},
	})

	resBlocked4 := &internal.ResultBlocked{
		List: testFltListID1,
		Rule: blockRule4,
	}

	resBlocked6 := &internal.ResultBlocked{
		List: testFltListID1,
		Rule: blockRule6,
	}

	testCases := []struct {
		wantRes internal.Result
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
			ri := &agd.RequestInfo{
				Messages: agdtest.NewConstructor(),
				Host:     tc.reqHost,
				QType:    tc.reqType,
			}

			req := &dns.Msg{
				Question: []dns.Question{{
					Name:   dns.Fqdn(tc.reqHost),
					Qtype:  tc.reqType,
					Qclass: dns.ClassINET,
				}},
			}

			ctx := context.Background()

			res, rerr := f.FilterRequest(ctx, req, ri)
			require.NoError(t, rerr)

			assert.Equal(t, tc.wantRes, res)
			assert.Equal(t, tc.wantRes, res)
		})
	}
}

func TestFilter_FilterRequest_safeSearch(t *testing.T) {
	const safeSearchIPStr = "1.2.3.4"

	const rewriteRule = filtertest.BlockRule + "$dnsrewrite=NOERROR;A;" + safeSearchIPStr

	var safeSearchIP net.IP = netip.MustParseAddr(safeSearchIPStr).AsSlice()
	cachePath, srvURL := filtertest.PrepareRefreshable(t, nil, rewriteRule, http.StatusOK)

	const fltListID = agd.FilterListIDGeneralSafeSearch

	gen := safesearch.New(&safesearch.Config{
		List: &agd.FilterList{
			URL: srvURL,
			ID:  fltListID,
		},
		Resolver: &agdtest.Resolver{
			OnLookupIP: func(
				_ context.Context,
				_ netutil.AddrFamily,
				_ string,
			) (ips []net.IP, err error) {
				return []net.IP{safeSearchIP}, nil
			},
		},
		ErrColl: &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, _ error) {
				panic("not implemented")
			},
		},
		CacheDir:  filepath.Dir(cachePath),
		CacheTTL:  1 * time.Minute,
		CacheSize: 100,
	})

	ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
	t.Cleanup(cancel)

	err := gen.Refresh(ctx, false)
	require.NoError(t, err)

	f := composite.New(&composite.Config{
		GeneralSafeSearch: gen,
	})

	ctx, req, ri := newReqData(t)
	res, err := f.FilterRequest(ctx, req, ri)
	require.NoError(t, err)

	wantResp := dnsservertest.NewResp(dns.RcodeSuccess, req, dnsservertest.SectionAnswer{
		dnsservertest.NewA(filtertest.ReqFQDN, agdtest.FilteredResponseTTLSec, safeSearchIP),
	})
	want := &internal.ResultModified{
		Msg:  wantResp,
		List: fltListID,
		Rule: filtertest.ReqHost,
	}
	assert.Equal(t, want, res)
}

func TestFilter_FilterRequest_services(t *testing.T) {
	const svcID = "test_service"

	svcRL, err := rulelist.NewImmutable(
		filtertest.BlockRule,
		agd.FilterListIDBlockedService,
		svcID,
		0,
		false,
	)
	require.NoError(t, err)

	f := composite.New(&composite.Config{
		ServiceLists: []*rulelist.Immutable{svcRL},
	})

	ctx, req, ri := newReqData(t)
	res, err := f.FilterRequest(ctx, req, ri)
	require.NoError(t, err)

	want := &internal.ResultBlocked{
		List: agd.FilterListIDBlockedService,
		Rule: svcID,
	}
	assert.Equal(t, want, res)
}

func TestFilter_FilterResponse(t *testing.T) {
	const cnameReqFQDN = "sub." + filtertest.ReqFQDN

	const (
		blockedCNAME   = filtertest.ReqHost
		blockedIPv4Str = "1.2.3.4"
		blockedIPv6Str = "1234::cdef"
		blockRules     = blockedCNAME + "\n" + blockedIPv4Str + "\n" + blockedIPv6Str + "\n"
	)

	var (
		blockedIPv4 net.IP = netip.MustParseAddr(blockedIPv4Str).AsSlice()
		blockedIPv6 net.IP = netip.MustParseAddr(blockedIPv6Str).AsSlice()
	)

	blockingRL := newFromStr(t, blockRules, testFltListID1)
	f := composite.New(&composite.Config{
		RuleLists: []*rulelist.Refreshable{blockingRL},
	})

	const ttl = agdtest.FilteredResponseTTLSec

	testCases := []struct {
		name     string
		reqFQDN  string
		wantRule agd.FilterRuleText
		respAns  dnsservertest.SectionAnswer
		qType    dnsmsg.RRType
	}{{
		name:     "cname",
		reqFQDN:  cnameReqFQDN,
		wantRule: filtertest.ReqHost,
		respAns: dnsservertest.SectionAnswer{
			dnsservertest.NewCNAME(cnameReqFQDN, ttl, filtertest.ReqFQDN),
			dnsservertest.NewA(filtertest.ReqFQDN, ttl, net.IP{1, 2, 3, 4}),
		},
		qType: dns.TypeA,
	}, {
		name:     "ipv4",
		reqFQDN:  filtertest.ReqFQDN,
		wantRule: blockedIPv4Str,
		respAns: dnsservertest.SectionAnswer{
			dnsservertest.NewA(filtertest.ReqFQDN, ttl, blockedIPv4),
		},
		qType: dns.TypeA,
	}, {
		name:     "ipv6",
		reqFQDN:  filtertest.ReqFQDN,
		wantRule: blockedIPv6Str,
		respAns: dnsservertest.SectionAnswer{
			dnsservertest.NewAAAA(filtertest.ReqFQDN, ttl, blockedIPv6),
		},
		qType: dns.TypeAAAA,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, req, ri := newReqData(t)
			req.Question[0].Name = tc.reqFQDN
			req.Question[0].Qtype = tc.qType

			resp := dnsservertest.NewResp(dns.RcodeSuccess, req, tc.respAns)
			res, err := f.FilterResponse(ctx, resp, ri)
			require.NoError(t, err)

			want := &internal.ResultBlocked{
				List: testFltListID1,
				Rule: tc.wantRule,
			}
			assert.Equal(t, want, res)
		})
	}
}
