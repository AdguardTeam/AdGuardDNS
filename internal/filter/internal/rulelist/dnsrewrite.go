package rulelist

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

// ProcessDNSRewrites processes $dnsrewrite rules dnsr and creates a filtering
// result, if id allows it.  res.List, if any, is set to id.
func ProcessDNSRewrites(
	messages *dnsmsg.Constructor,
	req *dns.Msg,
	dnsr []*rules.NetworkRule,
	host string,
	id agd.FilterListID,
) (res internal.Result) {
	if len(dnsr) == 0 || !id.SupportsDNSRewrite() {
		return nil
	}

	dnsRewriteResult := processDNSRewriteRules(dnsr)

	if resCanonName := dnsRewriteResult.CanonName; resCanonName != "" {
		// Rewrite the question name to a matched CNAME.
		if strings.EqualFold(resCanonName, host) {
			// A rewrite of a host to itself.
			return nil
		}

		req = dnsmsg.Clone(req)
		req.Question[0].Name = dns.Fqdn(resCanonName)

		return &internal.ResultModifiedRequest{
			Msg:  req,
			List: id,
			Rule: dnsRewriteResult.ResRuleText,
		}
	}

	if dnsRewriteResult.RCode != dns.RcodeSuccess {
		resp := messages.NewRespMsg(req)
		resp.Rcode = dnsRewriteResult.RCode

		return &internal.ResultModifiedResponse{
			Msg:  resp,
			List: id,
			Rule: dnsRewriteResult.ResRuleText,
		}
	}

	resp, err := filterDNSRewrite(messages, req, dnsRewriteResult)
	if err != nil {
		return nil
	}

	return &internal.ResultModifiedResponse{
		Msg:  resp,
		List: id,
	}
}

// dnsRewriteResult is the result of application of $dnsrewrite rules.
type dnsRewriteResult struct {
	Response    dnsRewriteResultResponse
	CanonName   string
	ResRuleText agd.FilterRuleText
	Rules       []*rules.NetworkRule
	RCode       rules.RCode
}

// dnsRewriteResultResponse is the collection of DNS response records
// the server returns.
type dnsRewriteResultResponse map[rules.RRType][]rules.RRValue

// processDNSRewriteRules processes DNS rewrite rules in dnsr.  The result will
// have either CanonName or RCode or Response set.
func processDNSRewriteRules(dnsr []*rules.NetworkRule) (res *dnsRewriteResult) {
	dnsrr := &dnsRewriteResult{
		Response: dnsRewriteResultResponse{},
	}

	for _, rule := range dnsr {
		dr := rule.DNSRewrite
		if dr.NewCNAME != "" {
			// NewCNAME rules have a higher priority than other rules.
			return &dnsRewriteResult{
				ResRuleText: agd.FilterRuleText(rule.RuleText),
				CanonName:   dr.NewCNAME,
			}
		}

		switch dr.RCode {
		case dns.RcodeSuccess:
			dnsrr.RCode = dr.RCode
			dnsrr.Response[dr.RRType] = append(dnsrr.Response[dr.RRType], dr.Value)
			dnsrr.Rules = append(dnsrr.Rules, rule)
		default:
			// RcodeRefused and other such codes have higher priority.  Return
			// immediately.
			return &dnsRewriteResult{
				ResRuleText: agd.FilterRuleText(rule.RuleText),
				RCode:       dr.RCode,
			}
		}
	}

	return dnsrr
}

// filterDNSRewrite handles dnsrewrite filters.  It constructs a DNS
// response and returns it.  dnsrr.RCode should be dns.RcodeSuccess and contain
// a non-empty dnsrr.Response.
func filterDNSRewrite(
	messages *dnsmsg.Constructor,
	req *dns.Msg,
	dnsrr *dnsRewriteResult,
) (resp *dns.Msg, err error) {
	if dnsrr.Response == nil {
		return nil, errors.Error("no dns rewrite rule responses")
	}

	resp = messages.NewRespMsg(req)

	rr := req.Question[0].Qtype
	values := dnsrr.Response[rr]
	for i, v := range values {
		var ans dns.RR
		ans, err = filterDNSRewriteResponse(messages, req, rr, v)
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
	messages *dnsmsg.Constructor,
	req *dns.Msg,
	rr rules.RRType,
	v rules.RRValue,
) (ans dns.RR, err error) {
	// TODO(a.garipov): As more types are added, we will probably want to
	// use a handler-oriented approach here.  So, think of a way to decouple
	// the answer generation logic from the Server.

	switch rr {
	case dns.TypeA, dns.TypeAAAA:
		return newAnsFromIP(messages, v, rr, req)
	case dns.TypePTR, dns.TypeTXT:
		return newAnsFromString(messages, v, rr, req)
	case dns.TypeMX:
		return newAnswerMX(messages, v, rr, req)
	case dns.TypeHTTPS, dns.TypeSVCB:
		return newAnsFromSVCB(messages, v, rr, req)
	case dns.TypeSRV:
		return newAnswerSRV(messages, v, rr, req)
	default:
		return nil, nil
	}
}

// newAnswerSRV returns a new resource record created from DNSSRV rules value.
func newAnswerSRV(
	messages *dnsmsg.Constructor,
	v rules.RRValue,
	rr rules.RRType,
	req *dns.Msg,
) (ans dns.RR, err error) {
	srv, ok := v.(*rules.DNSSRV)
	if !ok {
		return nil, fmt.Errorf("value for rr type %d has type %T, not *rules.DNSSRV", rr, v)
	}

	return messages.NewAnswerSRV(req, srv), nil
}

// newAnsFromSVCB returns a new resource record created from DNSSVCB rules value.
func newAnsFromSVCB(
	messages *dnsmsg.Constructor,
	v rules.RRValue,
	rr rules.RRType,
	req *dns.Msg,
) (ans dns.RR, err error) {
	svcb, ok := v.(*rules.DNSSVCB)
	if !ok {
		return nil, fmt.Errorf("value for rr type %d has type %T, not *rules.DNSSVCB", rr, v)
	}

	if rr == dns.TypeHTTPS {
		return messages.NewAnswerHTTPS(req, svcb), nil
	}

	return messages.NewAnswerSVCB(req, svcb), nil
}

// newAnsFromString returns a new resource record created from string value.
func newAnsFromString(
	messages *dnsmsg.Constructor,
	v rules.RRValue,
	rr rules.RRType,
	req *dns.Msg,
) (ans dns.RR, err error) {
	str, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("value for rr type %d has type %T, not string", rr, v)
	}

	if rr == dns.TypeTXT {
		return messages.NewAnswerTXT(req, []string{str})
	}

	return messages.NewAnswerPTR(req, str), nil
}

// newAnsFromIP returns a new resource record with an IP address.  ip must be an
// IPv4 or IPv6 address.
func newAnsFromIP(
	messages *dnsmsg.Constructor,
	v rules.RRValue,
	rr rules.RRType,
	req *dns.Msg,
) (ans dns.RR, err error) {
	ip, ok := v.(netip.Addr)
	if !ok {
		return nil, fmt.Errorf("value for rr type %d has type %T, not net.IP", rr, v)
	}

	target := req.Question[0].Name

	if rr == dns.TypeA {
		return messages.NewAnswerA(target, ip)
	}

	return messages.NewAnswerAAAA(target, ip)
}

// newAnswerMX returns a new resource record created from DNSMX rules value.
func newAnswerMX(
	messages *dnsmsg.Constructor,
	v rules.RRValue,
	rr rules.RRType,
	req *dns.Msg,
) (ans dns.RR, err error) {
	mx, ok := v.(*rules.DNSMX)
	if !ok {
		return nil, fmt.Errorf("value for rr type %d has type %T, not *rules.DNSMX", rr, v)
	}

	return messages.NewAnswerMX(req, mx), nil
}
