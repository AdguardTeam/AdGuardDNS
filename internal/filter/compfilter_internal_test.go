package filter

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompFilter_FilterRequest_badrequest(t *testing.T) {
	const (
		fltListID1 agd.FilterListID = "fl1"
		fltListID2 agd.FilterListID = "fl2"

		reqHost = "www.example.com"

		blockRule = "||example.com^"
	)

	rl1, err := newRuleListFltFromStr(blockRule, fltListID1)
	require.NoError(t, err)

	rl2, err := newRuleListFltFromStr("||example.com^$badfilter", fltListID2)
	require.NoError(t, err)

	req := &dns.Msg{
		Question: []dns.Question{{
			Name:   dns.Fqdn(reqHost),
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}

	testCases := []struct {
		name      string
		wantRes   Result
		ruleLists []*ruleListFilter
	}{{
		name:      "block",
		wantRes:   &ResultBlocked{List: fltListID1, Rule: blockRule},
		ruleLists: []*ruleListFilter{rl1},
	}, {
		name:      "badfilter_no_block",
		wantRes:   nil,
		ruleLists: []*ruleListFilter{rl2},
	}, {
		name:      "badfilter_removes_block",
		wantRes:   nil,
		ruleLists: []*ruleListFilter{rl1, rl2},
	}}

	ri := &agd.RequestInfo{
		Messages: &dnsmsg.Constructor{
			FilteredResponseTTL: 10 * time.Second,
		},
		Host:     reqHost,
		RemoteIP: testRemoteIP,
		QType:    dns.TypeA,
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := &compFilter{
				ruleLists: tc.ruleLists,
			}

			ctx := context.Background()

			res, rerr := f.FilterRequest(ctx, req, ri)
			require.NoError(t, rerr)

			assert.Equal(t, tc.wantRes, res)
		})
	}
}

func TestCompFilter_FilterRequest_hostsRules(t *testing.T) {
	const (
		fltListID agd.FilterListID = "fl1"

		reqHost4 = "www.example.com"
		reqHost6 = "www.example.net"

		blockRule4 = "127.0.0.1 www.example.com"
		blockRule6 = "::1 www.example.net"
	)

	const rules = blockRule4 + "\n" + blockRule6

	rl, err := newRuleListFltFromStr(rules, fltListID)
	require.NoError(t, err)

	f := &compFilter{
		ruleLists: []*ruleListFilter{rl},
	}

	testCases := []struct {
		wantRes Result
		name    string
		reqHost string
		reqType dnsmsg.RRType
	}{{
		wantRes: &ResultBlocked{List: fltListID, Rule: blockRule4},
		name:    "a",
		reqHost: reqHost4,
		reqType: dns.TypeA,
	}, {
		wantRes: &ResultBlocked{List: fltListID, Rule: blockRule6},
		name:    "aaaa",
		reqHost: reqHost6,
		reqType: dns.TypeAAAA,
	}, {
		wantRes: &ResultBlocked{List: fltListID, Rule: blockRule6},
		name:    "a_with_ipv6_rule",
		reqHost: reqHost6,
		reqType: dns.TypeA,
	}, {
		wantRes: &ResultBlocked{List: fltListID, Rule: blockRule4},
		name:    "aaaa_with_ipv4_rule",
		reqHost: reqHost4,
		reqType: dns.TypeAAAA,
	}, {
		wantRes: &ResultBlocked{List: fltListID, Rule: blockRule4},
		name:    "mx",
		reqHost: reqHost4,
		reqType: dns.TypeMX,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ri := &agd.RequestInfo{
				Messages: &dnsmsg.Constructor{
					FilteredResponseTTL: 10 * time.Second,
				},
				Host:     tc.reqHost,
				RemoteIP: testRemoteIP,
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

func TestCompFilter_FilterRequest_dnsrewrite(t *testing.T) {
	const (
		fltListID1 agd.FilterListID = "fl1"
		fltListID2 agd.FilterListID = "fl2"

		fltListIDCustom = agd.FilterListIDCustom

		reqHost = "www.example.com"

		blockRule             = "||example.com^"
		dnsRewriteRuleRefused = "||example.com^$dnsrewrite=REFUSED"
		dnsRewriteRuleCname   = "||example.com^$dnsrewrite=cname"
		dnsRewriteRule1       = "||example.com^$dnsrewrite=1.2.3.4"
		dnsRewriteRule2       = "||example.com^$dnsrewrite=1.2.3.5"
	)

	rl1, err := newRuleListFltFromStr(blockRule, fltListID1)
	require.NoError(t, err)

	rl2, err := newRuleListFltFromStr(dnsRewriteRuleRefused, fltListID2)
	require.NoError(t, err)

	rlCustomRefused, err := newRuleListFltFromStr(dnsRewriteRuleRefused, fltListIDCustom)
	require.NoError(t, err)

	rlCustomCname, err := newRuleListFltFromStr(dnsRewriteRuleCname, fltListIDCustom)
	require.NoError(t, err)

	rlCustom2, err := newRuleListFltFromStr(
		strings.Join([]string{dnsRewriteRule1, dnsRewriteRule2}, "\n"),
		fltListIDCustom,
	)
	require.NoError(t, err)

	question := dns.Question{
		Name:   dns.Fqdn(reqHost),
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}

	req := &dns.Msg{
		Question: []dns.Question{question},
	}

	testCases := []struct {
		name      string
		wantRes   Result
		ruleLists []*ruleListFilter
	}{{
		name:      "block",
		wantRes:   &ResultBlocked{List: fltListID1, Rule: blockRule},
		ruleLists: []*ruleListFilter{rl1},
	}, {
		name:      "dnsrewrite_no_effect",
		wantRes:   &ResultBlocked{List: fltListID1, Rule: blockRule},
		ruleLists: []*ruleListFilter{rl1, rl2},
	}, {
		name: "dnsrewrite_block",
		wantRes: &ResultModified{
			Msg:  dnsservertest.NewResp(dns.RcodeRefused, req, dnsservertest.RRSection{}),
			List: fltListIDCustom,
			Rule: dnsRewriteRuleRefused,
		},
		ruleLists: []*ruleListFilter{rl1, rl2, rlCustomRefused},
	}, {
		name: "dnsrewrite_cname",
		wantRes: &ResultModified{
			Msg: dnsservertest.NewResp(dns.RcodeSuccess, req, dnsservertest.RRSection{
				RRs: []dns.RR{
					dnsservertest.NewCNAME(reqHost, 10, "cname"),
				},
			}),
			List: fltListIDCustom,
			Rule: dnsRewriteRuleCname,
		},
		ruleLists: []*ruleListFilter{rl1, rl2, rlCustomCname},
	}, {
		name: "dnsrewrite_answers",
		wantRes: &ResultModified{
			Msg: dnsservertest.NewResp(dns.RcodeSuccess, req, dnsservertest.RRSection{
				RRs: []dns.RR{
					dnsservertest.NewA(reqHost, 10, net.IP{1, 2, 3, 4}),
					dnsservertest.NewA(reqHost, 10, net.IP{1, 2, 3, 5}),
				},
			}),
			List: fltListIDCustom,
			Rule: "",
		},
		ruleLists: []*ruleListFilter{rl1, rl2, rlCustom2},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := &compFilter{
				ruleLists: tc.ruleLists,
			}

			ctx := context.Background()
			ri := &agd.RequestInfo{
				Messages: &dnsmsg.Constructor{
					FilteredResponseTTL: 10 * time.Second,
				},
				Host:     reqHost,
				RemoteIP: testRemoteIP,
				QType:    dns.TypeA,
			}

			res, rerr := f.FilterRequest(ctx, req, ri)
			require.NoError(t, rerr)

			assert.Equal(t, tc.wantRes, res)
		})
	}
}
