package filter

import (
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_processDNSRewriteRules(t *testing.T) {
	cnameRule, _ := rules.NewNetworkRule("|cname^$dnsrewrite=new-cname", 1)
	aRecordRule, _ := rules.NewNetworkRule("|a-record^$dnsrewrite=127.0.0.1", 1)
	refusedRule, _ := rules.NewNetworkRule("|refused^$dnsrewrite=REFUSED", 1)

	testCases := []struct {
		name string
		want *DNSRewriteResult
		dnsr []*rules.NetworkRule
	}{{
		name: "empty",
		want: &DNSRewriteResult{
			Response: DNSRewriteResultResponse{},
		},
		dnsr: []*rules.NetworkRule{},
	}, {
		name: "cname",
		want: &DNSRewriteResult{
			ResRuleText: agd.FilterRuleText(cnameRule.RuleText),
			CanonName:   cnameRule.DNSRewrite.NewCNAME,
		},
		dnsr: []*rules.NetworkRule{
			cnameRule,
			aRecordRule,
			refusedRule,
		},
	}, {
		name: "refused",
		want: &DNSRewriteResult{
			ResRuleText: agd.FilterRuleText(refusedRule.RuleText),
			RCode:       refusedRule.DNSRewrite.RCode,
		},
		dnsr: []*rules.NetworkRule{
			aRecordRule,
			refusedRule,
		},
	}, {
		name: "a_record",
		want: &DNSRewriteResult{
			Rules: []*rules.NetworkRule{aRecordRule},
			RCode: aRecordRule.DNSRewrite.RCode,
			Response: DNSRewriteResultResponse{
				aRecordRule.DNSRewrite.RRType: []rules.RRValue{aRecordRule.DNSRewrite.Value},
			},
		},
		dnsr: []*rules.NetworkRule{aRecordRule},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := processDNSRewriteRules(tc.dnsr)
			assert.Equal(t, tc.want, got)
		})
	}
}

func Test_filterDNSRewrite(t *testing.T) {
	const reqHost = "www.example.com"

	cnameRule, _ := rules.NewNetworkRule("|cname^$dnsrewrite=new-cname", 1)
	aRecordRule, _ := rules.NewNetworkRule("|a-record^$dnsrewrite=127.0.0.1", 1)
	refusedRule, _ := rules.NewNetworkRule("|refused^$dnsrewrite=REFUSED", 1)

	messages := &dnsmsg.Constructor{
		FilteredResponseTTL: 10 * time.Second,
	}

	req := dnsservertest.NewReq(dns.Fqdn(reqHost), dns.TypeA, dns.ClassINET)

	testCases := []struct {
		dnsrr   *DNSRewriteResult
		want    *dns.Msg
		name    string
		wantErr string
	}{{
		dnsrr: &DNSRewriteResult{
			Response: DNSRewriteResultResponse{},
		},
		want:    dnsservertest.NewResp(dns.RcodeSuccess, req, dnsservertest.RRSection{}),
		name:    "empty",
		wantErr: "",
	}, {
		dnsrr: &DNSRewriteResult{
			Rules:     []*rules.NetworkRule{cnameRule},
			CanonName: cnameRule.DNSRewrite.NewCNAME,
		},
		want:    nil,
		name:    "cname",
		wantErr: "no dns rewrite rule responses",
	}, {
		dnsrr: &DNSRewriteResult{
			Rules: []*rules.NetworkRule{refusedRule},
			RCode: refusedRule.DNSRewrite.RCode,
		},
		want:    nil,
		name:    "refused",
		wantErr: "non-success answer",
	}, {
		dnsrr: &DNSRewriteResult{
			Rules: []*rules.NetworkRule{aRecordRule},
			RCode: aRecordRule.DNSRewrite.RCode,
			Response: DNSRewriteResultResponse{
				aRecordRule.DNSRewrite.RRType: []rules.RRValue{aRecordRule.DNSRewrite.Value},
			},
		},
		want: dnsservertest.NewResp(
			aRecordRule.DNSRewrite.RCode,
			req,
			dnsservertest.RRSection{
				RRs: []dns.RR{
					dnsservertest.NewA(reqHost, 10, net.IP{127, 0, 0, 1}),
				},
			},
		),
		name:    "a_record",
		wantErr: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := filterDNSRewrite(messages, req, tc.dnsrr)
			testutil.AssertErrorMsg(t, tc.wantErr, err)
			assert.Equal(t, tc.want, resp)
		})
	}
}
