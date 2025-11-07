package rulelist_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testDNSRequestID is the common message ID for all DNS messages.
const testDNSRequestID = 1

// testListID is common list id for all network rules.
const testListID = rules.ListID(testDNSRequestID)

// Common rewrite values for tests.
const (
	exchange     = "mail.com"
	exchangeFQDN = exchange + "."

	targetHost = "target.com"
	targetFQDN = targetHost + "."
)

// newDNSRequest is a helper that returns a DNS request with the given
// data and overrides its ID with testDNSRequestID.
func newDNSRequest(tb testing.TB, host string, qt dnsmsg.RRType) (req *dns.Msg) {
	tb.Helper()

	req = dnsservertest.NewReq(host, qt, dns.ClassINET)
	req.Id = testDNSRequestID

	return req
}

// newRule is a helper, that returns a NetworkRule generated from string, and
// sets its list ID to a common value.
func newRule(tb testing.TB, rule string) (r *rules.NetworkRule) {
	tb.Helper()

	r, err := rules.NewNetworkRule(rule, testListID)
	require.NoError(tb, err)

	return r
}

// newResultModifiedResponse is a helper that returns a ResultModifiedResponse
// with the default list ID and a dns.Msg containing the given data.  request
// must not be nil.
func newResultModifiedResponse(
	tb testing.TB,
	rcode rules.RCode,
	request *dns.Msg,
	ans ...dnsservertest.RRSection,
) (resp *filter.ResultModifiedResponse) {
	tb.Helper()

	return &filter.ResultModifiedResponse{
		List: filtertest.RuleListID1,
		Msg:  dnsservertest.NewResp(rcode, request, ans...),
	}
}

func TestProccessDNSRewrites_RRTypes(t *testing.T) {
	t.Parallel()

	var (
		reqA    = newDNSRequest(t, filtertest.HostSafeSearchGeneralIPv4, dns.TypeA)
		reqAAAA = newDNSRequest(t, filtertest.HostSafeSearchGeneralIPv6, dns.TypeAAAA)
		reqTXT  = newDNSRequest(t, filtertest.Host, dns.TypeTXT)
		reqSRV  = newDNSRequest(t, filtertest.Host, dns.TypeSRV)
		reqSVCB = newDNSRequest(t, filtertest.Host, dns.TypeSVCB)
		reqMX   = newDNSRequest(t, filtertest.Host, dns.TypeMX)

		ansA = dnsservertest.SectionAnswer{
			dnsservertest.NewA(
				filtertest.FQDNSafeSearchGeneralIPv4,
				10,
				filtertest.IPv4SafeSearchRepl,
			),
		}
		ansAAAA = dnsservertest.SectionAnswer{
			dnsservertest.NewAAAA(
				filtertest.FQDNSafeSearchGeneralIPv6,
				10,
				filtertest.IPv6SafeSearchRepl,
			),
		}

		srv  = dnsservertest.NewSRV(filtertest.Host, 10, targetFQDN, 1, 1, 29)
		svcb = dnsservertest.NewSVCB(filtertest.Host, 10, targetFQDN, 1)
	)

	testCases := []struct {
		result filter.Result
		rule   *rules.NetworkRule
		name   string
		host   string
		qtype  dnsmsg.RRType
	}{{
		name:   "type_a",
		host:   filtertest.HostSafeSearchGeneralIPv4,
		qtype:  dns.TypeA,
		rule:   newRule(t, filtertest.RuleSafeSearchGeneralIPv4Str),
		result: newResultModifiedResponse(t, dns.RcodeSuccess, reqA, ansA),
	}, {
		name:   "type_aaaa",
		host:   filtertest.HostSafeSearchGeneralIPv6,
		qtype:  dns.TypeAAAA,
		rule:   newRule(t, filtertest.RuleSafeSearchGeneralIPv6Str),
		result: newResultModifiedResponse(t, dns.RcodeSuccess, reqAAAA, ansAAAA),
	}, {
		name:  "type_txt",
		host:  filtertest.Host,
		qtype: dns.TypeTXT,
		rule:  newRule(t, "||"+filtertest.Host+"^$dnsrewrite=NOERROR;TXT;rr_value"),
		result: newResultModifiedResponse(
			t,
			dns.RcodeSuccess,
			reqTXT,
			dnsservertest.SectionAnswer{dnsservertest.NewTXT(filtertest.FQDN, 10, "rr_value")},
		),
	}, {
		name:  "type_mx",
		host:  filtertest.Host,
		qtype: dns.TypeMX,
		rule:  newRule(t, "||"+filtertest.Host+"^$dnsrewrite=NOERROR;MX;1 "+exchange),
		result: newResultModifiedResponse(
			t,
			dns.RcodeSuccess,
			reqMX,
			dnsservertest.SectionAnswer{
				dnsservertest.NewMX(filtertest.FQDN, 10, 1, exchangeFQDN),
			},
		),
	}, {
		name:  "type_srv",
		host:  filtertest.Host,
		qtype: dns.TypeSRV,
		rule:  newRule(t, "||"+filtertest.Host+" ^$dnsrewrite=NOERROR;SRV;1 1 29 "+targetHost),
		result: newResultModifiedResponse(
			t,
			dns.RcodeSuccess,
			reqSRV,
			dnsservertest.SectionAnswer{srv},
		),
	}, {
		name:  "type_svcb",
		host:  filtertest.Host,
		qtype: dns.TypeSVCB,
		rule:  newRule(t, "||"+filtertest.Host+"^$dnsrewrite=NOERROR;SVCB;1 "+targetHost),
		result: newResultModifiedResponse(
			t,
			dns.RcodeSuccess,
			reqSVCB,
			dnsservertest.SectionAnswer{svcb},
		),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := filtertest.NewRequest(t, "", tc.host, filtertest.IPv4Client, tc.qtype)
			req.DNS.Id = testDNSRequestID
			dnsr := []*rules.NetworkRule{tc.rule}
			res := rulelist.ProcessDNSRewrites(req, dnsr, filtertest.RuleListID1)
			assert.Equal(t, tc.result, res)
		})
	}
}

func TestProccessDNSRewrites_Other(t *testing.T) {
	t.Parallel()

	var (
		cnameRule = "||" + filtertest.HostDangerous + "^$dnsrewrite=" + filtertest.Host
		rcodeRule = "||" + filtertest.Host + "^$dnsrewrite=REFUSED;;"
	)

	reqA := newDNSRequest(t, filtertest.Host, dns.TypeA)
	testCases := []struct {
		result filter.Result
		rule   *rules.NetworkRule
		name   string
		host   string
	}{{
		name: "cname",
		host: filtertest.HostDangerous,
		rule: newRule(t, cnameRule),
		result: &filter.ResultModifiedRequest{
			List: filtertest.RuleListID1,
			Msg:  newDNSRequest(t, filtertest.FQDN, dns.TypeA),
			Rule: filter.RuleText(cnameRule),
		},
	}, {
		name:   "empty_rules",
		host:   filtertest.Host,
		rule:   nil,
		result: nil,
	}, {
		name:   "equal_cname",
		host:   filtertest.Host,
		rule:   newRule(t, "||"+filtertest.Host+"^$dnsrewrite="+filtertest.Host),
		result: nil,
	}, {
		name: "rcode",
		host: filtertest.Host,
		rule: newRule(t, rcodeRule),
		result: &filter.ResultModifiedResponse{
			List: filtertest.RuleListID1,
			Msg:  dnsservertest.NewResp(dns.RcodeRefused, reqA),
			Rule: filter.RuleText(rcodeRule),
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := filtertest.NewRequest(t, "", tc.host, filtertest.IPv4Client, dns.TypeA)
			req.DNS.Id = testDNSRequestID
			var dnsr []*rules.NetworkRule
			if tc.rule != nil {
				dnsr = []*rules.NetworkRule{tc.rule}
			}

			res := rulelist.ProcessDNSRewrites(req, dnsr, filtertest.RuleListID1)
			assert.Equal(t, tc.result, res)
		})
	}
}

func BenchmarkProcessDNSRewrite(b *testing.B) {
	benchCases := []struct {
		rule *rules.NetworkRule
		name string
	}{{
		name: "cname",
		rule: newRule(b, "||"+filtertest.Host+"^$dnsrewrite="+filtertest.HostDangerous),
	}, {
		name: "rcode",
		rule: newRule(b, "||"+filtertest.Host+"^$dnsrewrite=REFUSED;;"),
	}, {
		name: "type_a",
		rule: newRule(b, "||"+filtertest.Host+"^$dnsrewrite="+filtertest.IPv4ClientStr),
	}}

	req := filtertest.NewRequest(b, "", filtertest.Host, filtertest.IPv4Client, dns.TypeA)
	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			var result filter.Result
			dnsr := []*rules.NetworkRule{bc.rule}

			b.ReportAllocs()
			for b.Loop() {
				result = rulelist.ProcessDNSRewrites(req, dnsr, filtertest.RuleListID1)
			}

			assert.NotNil(b, result)
		})
	}

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist
	//	cpu: Apple M3
	//	BenchmarkProcessDNSRewrite/cname-8         	 9117697	       111.7 ns/op	     280 B/op	       5 allocs/op
	//	BenchmarkProcessDNSRewrite/rcode-8         	16215256	        75.06 ns/op	     264 B/op	       4 allocs/op
	//	BenchmarkProcessDNSRewrite/type_a-8        	 5742392	       214.6 ns/op	     656 B/op	       9 allocs/op
}
