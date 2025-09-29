package rulelist

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

// ProcessDNSRewrites processes $dnsrewrite rules dnsr and creates a filtering
// result, if id allows it.  res.List, if any, is set to id.
func ProcessDNSRewrites(
	req *filter.Request,
	dnsr []*rules.NetworkRule,
	id filter.ID,
) (res filter.Result) {
	if len(dnsr) == 0 {
		return nil
	}

	// Use a value and not a pointer so that the dnsRewriteResult value stays on
	// the stack and not produce an extra allocation.
	dnsRwRes := dnsRewriteResult{
		Response: dnsRewriteResultResponse{},
	}
	processDNSRewriteRules(dnsr, &dnsRwRes)

	if resCanonName := dnsRwRes.CanonName; resCanonName != "" {
		// Rewrite the question name to a matched CNAME.
		if strings.EqualFold(resCanonName, req.Host) {
			// A rewrite of a host to itself.
			return nil
		}

		modReq := dnsmsg.Clone(req.DNS)
		modReq.Question[0].Name = dns.Fqdn(resCanonName)

		return &filter.ResultModifiedRequest{
			Msg:  modReq,
			List: id,
			Rule: dnsRwRes.ResRuleText,
		}
	}

	if dnsRwRes.RCode != dns.RcodeSuccess {
		// #nosec G115 -- The value of dnsRewriteResult.RCode comes from the
		// urlfilter package, where it either parsed by [dns.StringToRcode] or
		// defined statically.
		resp := req.Messages.NewBlockedRespRCode(req.DNS, dnsmsg.RCode(dnsRwRes.RCode))

		return &filter.ResultModifiedResponse{
			Msg:  resp,
			List: id,
			Rule: dnsRwRes.ResRuleText,
		}
	}

	resp, err := filterDNSRewrite(req, &dnsRwRes)
	if err != nil {
		return nil
	}

	return &filter.ResultModifiedResponse{
		Msg:  resp,
		List: id,
	}
}

// dnsRewriteResult is the result of application of $dnsrewrite rules.
type dnsRewriteResult struct {
	Response    dnsRewriteResultResponse
	CanonName   string
	ResRuleText filter.RuleText
	RCode       rules.RCode
}

// dnsRewriteResultResponse is the collection of DNS response records
// the server returns.
type dnsRewriteResultResponse map[rules.RRType][]rules.RRValue

// processDNSRewriteRules processes DNS rewrite rules in dnsr.  res will have
// either CanonName or RCode or Response set.  res and res.Response must not be
// nil.
func processDNSRewriteRules(dnsr []*rules.NetworkRule, res *dnsRewriteResult) {
	for _, rule := range dnsr {
		dr := rule.DNSRewrite
		if dr.NewCNAME != "" {
			// NewCNAME rules have a higher priority than other rules.
			res.CanonName = dr.NewCNAME
			res.ResRuleText = filter.RuleText(rule.Text())

			return
		}

		if dr.RCode != dns.RcodeSuccess {
			// [dns.RcodeRefused] and other such codes have higher priority.
			// Set and return immediately.
			res.ResRuleText = filter.RuleText(rule.Text())
			res.RCode = dr.RCode

			return
		}

		res.Response[dr.RRType] = append(res.Response[dr.RRType], dr.Value)
		res.RCode = dr.RCode
	}
}

// filterDNSRewrite handles dnsrewrite filters.  It constructs a DNS response
// and returns it.  req and res must not be nil.  res.RCode should be
// [dns.RcodeSuccess] and contain a non-empty Response.
func filterDNSRewrite(req *filter.Request, res *dnsRewriteResult) (resp *dns.Msg, err error) {
	if res.Response == nil {
		return nil, errors.Error("no dns rewrite rule responses")
	}

	// TODO(e.burkov):  Use a constructor method that adds a SOA for caching if
	// necessary.
	dnsReq := req.DNS
	resp = req.Messages.NewBlockedRespRCode(dnsReq, dns.RcodeSuccess)

	rr := dnsReq.Question[0].Qtype
	values := res.Response[rr]
	for i, v := range values {
		var ans dns.RR
		ans, err = filterDNSRewriteResponse(req, rr, v)
		if err != nil {
			return nil, fmt.Errorf("dns rewrite response for %d[%d]: %w", rr, i, err)
		} else if ans == nil {
			// TODO(e.burkov):  Currently, urlfilter returns all the matched
			// $dnsrewrite rules including invalid ones.  Fix this behavior.
			continue
		}

		resp.Answer = append(resp.Answer, ans)
	}

	return resp, nil
}

// filterDNSRewriteResponse handles a single DNS rewrite response entry.
// It returns the properly constructed answer resource record.
func filterDNSRewriteResponse(
	req *filter.Request,
	rr rules.RRType,
	v rules.RRValue,
) (ans dns.RR, err error) {
	// TODO(a.garipov): As more types are added, we will probably want to
	// use a handler-oriented approach here.  So, think of a way to decouple
	// the answer generation logic from the Server.

	switch rr {
	case dns.TypeA, dns.TypeAAAA:
		return newAnsFromIP(req, v, rr)
	case dns.TypePTR, dns.TypeTXT:
		return newAnsFromString(req, v, rr)
	case dns.TypeMX:
		return newAnswerMX(req, v, rr)
	case dns.TypeHTTPS, dns.TypeSVCB:
		return newAnsFromSVCB(req, v, rr)
	case dns.TypeSRV:
		return newAnswerSRV(req, v, rr)
	default:
		return nil, nil
	}
}

// newAnswerSRV returns a new resource record created from DNSSRV rules value.
func newAnswerSRV(req *filter.Request, v rules.RRValue, rr rules.RRType) (ans dns.RR, err error) {
	srv, ok := v.(*rules.DNSSRV)
	if !ok {
		return nil, fmt.Errorf("value for rr type %d has type %T, not *rules.DNSSRV", rr, v)
	}

	return req.Messages.NewAnswerSRV(req.DNS, srv), nil
}

// newAnsFromSVCB returns a new resource record created from DNSSVCB rules value.
func newAnsFromSVCB(req *filter.Request, v rules.RRValue, rr rules.RRType) (ans dns.RR, err error) {
	svcb, ok := v.(*rules.DNSSVCB)
	if !ok {
		return nil, fmt.Errorf("value for rr type %d has type %T, not *rules.DNSSVCB", rr, v)
	}

	if rr == dns.TypeHTTPS {
		return req.Messages.NewAnswerHTTPS(req.DNS, svcb), nil
	}

	return req.Messages.NewAnswerSVCB(req.DNS, svcb), nil
}

// newAnsFromString returns a new resource record created from string value.
func newAnsFromString(
	req *filter.Request,
	v rules.RRValue,
	rr rules.RRType,
) (ans dns.RR, err error) {
	str, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("value for rr type %d has type %T, not string", rr, v)
	}

	if rr == dns.TypeTXT {
		return req.Messages.NewAnswerTXT(req.DNS, []string{str})
	}

	return req.Messages.NewAnswerPTR(req.DNS, str), nil
}

// newAnsFromIP returns a new resource record with an IP address.  ip must be an
// IPv4 or IPv6 address.
func newAnsFromIP(req *filter.Request, v rules.RRValue, rr rules.RRType) (ans dns.RR, err error) {
	ip, ok := v.(netip.Addr)
	if !ok {
		return nil, fmt.Errorf("value for rr type %d has type %T, not net.IP", rr, v)
	}

	target := req.DNS.Question[0].Name

	if rr == dns.TypeA {
		return req.Messages.NewAnswerA(target, ip)
	}

	return req.Messages.NewAnswerAAAA(target, ip)
}

// newAnswerMX returns a new resource record created from DNSMX rules value.
func newAnswerMX(req *filter.Request, v, rr rules.RRValue) (ans dns.RR, err error) {
	mx, ok := v.(*rules.DNSMX)
	if !ok {
		return nil, fmt.Errorf("value for rr type %d has type %T, not *rules.DNSMX", rr, v)
	}

	return req.Messages.NewAnswerMX(req.DNS, mx), nil
}
