// Package composite implements a composite filter based on several types of
// filters and the logic of the filter application.
package composite

import (
	"context"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/miekg/dns"
)

// Filter is a composite filter based on several types of safe-search and
// rule-list filters.
type Filter struct {
	// custom is the custom rule-list filter of the profile, if any.
	custom filter.Custom

	// ruleLists are the enabled rule-list filters of the profile or filtering
	// group.
	ruleLists []*rulelist.Refreshable

	// svcLists are the rule-list filters of the profile's enabled blocked
	// services, if any.
	svcLists []*rulelist.Immutable

	// reqFilters are the safe-browsing and safe-search request filters in the
	// composite filter.
	reqFilters []RequestFilter
}

// Config is the configuration structure for the composite filter.
type Config struct {
	// SafeBrowsing is the safe-browsing filter to apply, if any.
	SafeBrowsing RequestFilter

	// AdultBlocking is the adult-content filter to apply, if any.
	AdultBlocking RequestFilter

	// NewRegisteredDomains is the newly registered domains filter to apply, if
	// any.
	NewRegisteredDomains RequestFilter

	// GeneralSafeSearch is the general safe-search filter to apply, if any.
	GeneralSafeSearch RequestFilter

	// YouTubeSafeSearch is the youtube safe-search filter to apply, if any.
	YouTubeSafeSearch RequestFilter

	// Custom is the custom rule-list filter of the profile, if any.
	Custom filter.Custom

	// RuleLists are the enabled rule-list filters of the profile or filtering
	// group, if any.  All items must not be nil.
	RuleLists []*rulelist.Refreshable

	// ServiceLists are the rule-list filters of the profile's enabled blocked
	// services, if any.  All items must not be nil.
	ServiceLists []*rulelist.Immutable
}

// RequestFilter can filter a request based on the request info.
type RequestFilter interface {
	// FilterRequest filters a DNS request based on the information provided
	// about the request.  req must be valid.
	FilterRequest(ctx context.Context, req *filter.Request) (r filter.Result, err error)
}

// New returns a new composite filter.  c must not be nil.
func New(c *Config) (f *Filter) {
	f = &Filter{
		custom:    c.Custom,
		ruleLists: c.RuleLists,
		svcLists:  c.ServiceLists,
	}

	// DO NOT change the order of request filters without necessity.
	f.reqFilters = appendIfNotNil(f.reqFilters, c.SafeBrowsing)
	f.reqFilters = appendIfNotNil(f.reqFilters, c.AdultBlocking)
	f.reqFilters = appendIfNotNil(f.reqFilters, c.GeneralSafeSearch)
	f.reqFilters = appendIfNotNil(f.reqFilters, c.YouTubeSafeSearch)
	f.reqFilters = appendIfNotNil(f.reqFilters, c.NewRegisteredDomains)

	return f
}

// appendIfNotNil appends flt to flts if flt is not nil.
func appendIfNotNil(flts []RequestFilter, flt RequestFilter) (res []RequestFilter) {
	if flt != nil {
		flts = append(flts, flt)
	}

	return flts
}

// type check
var _ filter.Interface = (*Filter)(nil)

// FilterRequest implements the [filter.Interface] interface for *Filter.  The
// order in which the filters are applied is the following:
//
//  1. Custom filter.
//  2. Rule-list filters.
//  3. Blocked-service filters.
//  4. Dangerous-domains filter.
//  5. Adult-content filter.
//  6. General safe-search filter.
//  7. YouTube safe-search filter.
//  8. Newly-registered domains filter.
//
// If f is empty, it returns nil with no error.
func (f *Filter) FilterRequest(
	ctx context.Context,
	req *filter.Request,
) (r filter.Result, err error) {
	// Prepare common data for filters.  Firstly, check the profile's rule-list
	// filtering, the custom rules, and the rules from blocked services
	// settings.
	rlRes := f.filterReqWithRuleLists(ctx, req)
	switch flRes := rlRes.(type) {
	case *filter.ResultAllowed:
		// Skip any additional filtering if the domain is explicitly allowed by
		// user's custom rule.
		if flRes.List == filter.IDCustom {
			return flRes, nil
		}
	case
		*filter.ResultBlocked,
		*filter.ResultModifiedRequest,
		*filter.ResultModifiedResponse:
		// Skip any additional filtering if the query is already blocked or
		// modified.
		return flRes, nil
	default:
		// Go on.
	}

	for _, rf := range f.reqFilters {
		r, err = rf.FilterRequest(ctx, req)
		if err != nil {
			return nil, err
		} else if r != nil {
			return r, nil
		}
	}

	// Thirdly, return the previously obtained filter list result.
	return rlRes, nil
}

// filterReqWithRuleLists filters one question's information through all rule
// list filters of the composite filter.  req must not be nil.
func (f *Filter) filterReqWithRuleLists(
	ctx context.Context,
	req *filter.Request,
) (r filter.Result) {
	ip, host, qt := req.RemoteIP, req.Host, req.QType

	// TODO(a.garipov):  Consider adding a pool of results to the default
	// storage and use it here.
	ufRes := newURLFilterResult()
	if f.custom != nil {
		id := filter.IDCustom

		// Only use the device name for custom filters of profiles with devices.
		dr := f.custom.DNSResult(ctx, ip, req.ClientName, host, qt, false)
		mod := rulelist.ProcessDNSRewrites(req, dr.DNSRewrites(), id)
		if mod != nil {
			// Process the DNS rewrites of the custom list and return them
			// first, because custom rules have priority over other rules.
			return mod
		}

		ufRes.add(id, "", dr)
	}

	for _, rl := range f.ruleLists {
		id, _ := rl.ID()
		dr := rl.DNSResult(ip, "", host, qt, false)
		mod := rulelist.ProcessDNSRewrites(req, dr.DNSRewrites(), id)
		if mod != nil {
			// DNS rewrites have higher priority, so a modified request must be
			// returned immediately.
			return mod
		}

		ufRes.add(id, "", dr)
	}

	for _, rl := range f.svcLists {
		id, svcID := rl.ID()
		ufRes.add(id, svcID, rl.DNSResult(ip, "", host, qt, false))
	}

	return ufRes.toInternal(qt)
}

// FilterResponse implements the [filter.Interface] interface for *Filter.  It
// returns the action created from the filter list network rule with the highest
// priority.  If f is empty, it returns nil with no error.  Note that rewrite
// results are not applied to responses.
func (f *Filter) FilterResponse(
	ctx context.Context,
	resp *filter.Response,
) (r filter.Result, err error) {
	for _, ans := range resp.DNS.Answer {
		r = f.filterAnswer(ctx, resp, ans)
		if r != nil {
			break
		}
	}

	return r, nil
}

// filterAnswer filters a single answer of a response.  r is not nil if the
// response is filtered.
func (f *Filter) filterAnswer(
	ctx context.Context,
	resp *filter.Response,
	ans dns.RR,
) (r filter.Result) {
	if rr, ok := ans.(*dns.HTTPS); ok {
		return f.filterHTTPSAnswer(ctx, resp, rr)
	}

	host, rrType, ok := parseRespAnswer(ans)
	if !ok {
		return nil
	}

	return f.filterRespWithRuleLists(ctx, resp, host, rrType)
}

// filterRespWithRuleLists filters one answer's information through all
// rule-list filters of the composite filter.
func (f *Filter) filterRespWithRuleLists(
	ctx context.Context,
	resp *filter.Response,
	host string,
	rrType dnsmsg.RRType,
) (r filter.Result) {
	ufRes := newURLFilterResult()
	for _, rl := range f.ruleLists {
		id, _ := rl.ID()
		ufRes.add(id, "", rl.DNSResult(resp.RemoteIP, "", host, rrType, true))
	}

	if f.custom != nil {
		dr := f.custom.DNSResult(ctx, resp.RemoteIP, resp.ClientName, host, rrType, true)
		ufRes.add(filter.IDCustom, "", dr)
	}

	for _, rl := range f.svcLists {
		id, svcID := rl.ID()
		ufRes.add(id, svcID, rl.DNSResult(resp.RemoteIP, "", host, rrType, true))
	}

	return ufRes.toInternal(rrType)
}

// filterHTTPSAnswer filters HTTPS answers information through all rule list
// filters of the composite filter.
func (f *Filter) filterHTTPSAnswer(
	ctx context.Context,
	resp *filter.Response,
	rr *dns.HTTPS,
) (r filter.Result) {
	for _, kv := range rr.Value {
		switch kv.Key() {
		case dns.SVCB_IPV4HINT, dns.SVCB_IPV6HINT:
			r = f.filterSVCBHint(ctx, kv.String(), resp)
			if r != nil {
				return r
			}
		default:
			// Go on.
		}
	}

	return nil
}

// filterSVCBHint filters SVCB hint information through all rule list filters of
// the composite filter.
func (f *Filter) filterSVCBHint(
	ctx context.Context,
	hint string,
	resp *filter.Response,
) (r filter.Result) {
	for _, s := range strings.Split(hint, ",") {
		r = f.filterRespWithRuleLists(ctx, resp, s, dns.TypeHTTPS)
		if r != nil {
			return r
		}
	}

	return nil
}

// parseRespAnswer parses hostname and rrType from the answer if there are any.
// If ans is of a type that doesn't have an IP address or a hostname in it, ok
// is false.
func parseRespAnswer(ans dns.RR) (hostname string, rrType dnsmsg.RRType, ok bool) {
	switch ans := ans.(type) {
	case *dns.A:
		return ans.A.String(), dns.TypeA, true
	case *dns.AAAA:
		return ans.AAAA.String(), dns.TypeAAAA, true
	case *dns.CNAME:
		return strings.TrimSuffix(ans.Target, "."), dns.TypeCNAME, true
	default:
		return "", dns.TypeNone, false
	}
}
