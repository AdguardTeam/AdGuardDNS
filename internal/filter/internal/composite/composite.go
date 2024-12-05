// Package composite implements a composite filter based on several types of
// filters and the logic of the filter application.
package composite

import (
	"context"
	"fmt"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/safesearch"
	"github.com/miekg/dns"
)

// Filter is a composite filter based on several types of safe-search and
// rule-list filters.
type Filter struct {
	// custom is the custom rule-list filter of the profile, if any.
	custom *rulelist.Immutable

	// ruleLists are the enabled rule-list filters of the profile or filtering
	// group.
	ruleLists []*rulelist.Refreshable

	// svcLists are the rule-list filters of the profile's enabled blocked
	// services, if any.
	svcLists []*rulelist.Immutable

	// reqFilters are the safe-browsing and safe-search request filters in the
	// composite filter.
	reqFilters []internal.RequestFilter
}

// Config is the configuration structure for the composite filter.
type Config struct {
	// SafeBrowsing is the safe-browsing filter to apply, if any.
	SafeBrowsing *hashprefix.Filter

	// AdultBlocking is the adult-content filter to apply, if any.
	AdultBlocking *hashprefix.Filter

	// NewRegisteredDomains is the newly registered domains filter to apply, if
	// any.
	NewRegisteredDomains *hashprefix.Filter

	// GeneralSafeSearch is the general safe-search filter to apply, if any.
	GeneralSafeSearch *safesearch.Filter

	// YouTubeSafeSearch is the youtube safe-search filter to apply, if any.
	YouTubeSafeSearch *safesearch.Filter

	// Custom is the custom rule-list filter of the profile, if any.
	Custom *rulelist.Immutable

	// RuleLists are the enabled rule-list filters of the profile or filtering
	// group, if any.  All items must not be nil.
	RuleLists []*rulelist.Refreshable

	// ServiceLists are the rule-list filters of the profile's enabled blocked
	// services, if any.  All items must not be nil.
	ServiceLists []*rulelist.Immutable
}

// New returns a new composite filter.  c must not be nil.
func New(c *Config) (f *Filter) {
	f = &Filter{
		custom:    c.Custom,
		ruleLists: c.RuleLists,
		svcLists:  c.ServiceLists,
	}

	// DO NOT change the order of request filters without necessity.
	f.reqFilters = appendReqFilter(f.reqFilters, c.SafeBrowsing)
	f.reqFilters = appendReqFilter(f.reqFilters, c.AdultBlocking)
	f.reqFilters = appendReqFilter(f.reqFilters, c.GeneralSafeSearch)
	f.reqFilters = appendReqFilter(f.reqFilters, c.YouTubeSafeSearch)
	f.reqFilters = appendReqFilter(f.reqFilters, c.NewRegisteredDomains)

	return f
}

// appendReqFilter appends flt to flts if flt is not nil.
func appendReqFilter[T *hashprefix.Filter | *safesearch.Filter](
	flts []internal.RequestFilter,
	flt T,
) (res []internal.RequestFilter) {
	if flt != nil {
		flts = append(flts, internal.RequestFilter(flt))
	}

	return flts
}

// type check
var _ filter.Interface = (*Filter)(nil)

// FilterRequest implements the [internal.Interface] interface for *Filter.  The
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
	req *internal.Request,
) (r internal.Result, err error) {
	// Prepare common data for filters.  Firstly, check the profile's rule-list
	// filtering, the custom rules, and the rules from blocked services
	// settings.
	rlRes := f.filterReqWithRuleLists(req)
	switch flRes := rlRes.(type) {
	case *internal.ResultAllowed:
		// Skip any additional filtering if the domain is explicitly allowed by
		// user's custom rule.
		if flRes.List == internal.IDCustom {
			return flRes, nil
		}
	case
		*internal.ResultBlocked,
		*internal.ResultModifiedRequest,
		*internal.ResultModifiedResponse:
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
func (f *Filter) filterReqWithRuleLists(req *internal.Request) (r internal.Result) {
	ip, host, qt := req.RemoteIP, req.Host, req.QType

	ufRes := &rulelist.URLFilterResult{}
	if f.custom != nil {
		id := internal.IDCustom

		// Only use the device name for custom filters of profiles with devices.
		dr := f.custom.DNSResult(ip, req.ClientName, host, qt, false)
		mod := rulelist.ProcessDNSRewrites(req, dr.DNSRewrites(), id)
		if mod != nil {
			// Process the DNS rewrites of the custom list and return them
			// first, because custom rules have priority over other rules.
			return mod
		}

		ufRes.Add(dr)
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

		ufRes.Add(dr)
	}

	for _, rl := range f.svcLists {
		ufRes.Add(rl.DNSResult(ip, "", host, qt, false))
	}

	return ufRes.ToInternal(f, qt)
}

// FilterResponse implements the [internal.Interface] interface for *Filter.  It
// returns the action created from the filter list network rule with the highest
// priority.  If f is empty, it returns nil with no error.  Note that rewrite
// results are not applied to responses.
func (f *Filter) FilterResponse(
	_ context.Context,
	resp *internal.Response,
) (r internal.Result, err error) {
	for _, ans := range resp.DNS.Answer {
		r = f.filterAnswer(resp, ans)
		if r != nil {
			break
		}
	}

	return r, nil
}

// filterAnswer filters a single answer of a response.  r is not nil if the
// response is filtered.
func (f *Filter) filterAnswer(resp *internal.Response, ans dns.RR) (r internal.Result) {
	if rr, ok := ans.(*dns.HTTPS); ok {
		return f.filterHTTPSAnswer(resp, rr)
	}

	host, rrType, ok := parseRespAnswer(ans)
	if !ok {
		return nil
	}

	return f.filterRespWithRuleLists(resp, host, rrType)
}

// filterRespWithRuleLists filters one answer's information through all
// rule-list filters of the composite filter.
func (f *Filter) filterRespWithRuleLists(
	resp *internal.Response,
	host string,
	rrType dnsmsg.RRType,
) (r internal.Result) {
	ufRes := &rulelist.URLFilterResult{}
	for _, rl := range f.ruleLists {
		ufRes.Add(rl.DNSResult(resp.RemoteIP, "", host, rrType, true))
	}

	if f.custom != nil {
		ufRes.Add(f.custom.DNSResult(resp.RemoteIP, resp.ClientName, host, rrType, true))
	}

	for _, rl := range f.svcLists {
		ufRes.Add(rl.DNSResult(resp.RemoteIP, "", host, rrType, true))
	}

	return ufRes.ToInternal(f, rrType)
}

// filterHTTPSAnswer filters HTTPS answers information through all rule list
// filters of the composite filter.
func (f *Filter) filterHTTPSAnswer(resp *internal.Response, rr *dns.HTTPS) (r internal.Result) {
	for _, kv := range rr.Value {
		switch kv.Key() {
		case dns.SVCB_IPV4HINT, dns.SVCB_IPV6HINT:
			r = f.filterSVCBHint(kv.String(), resp)
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
func (f *Filter) filterSVCBHint(hint string, resp *internal.Response) (r internal.Result) {
	for _, s := range strings.Split(hint, ",") {
		r = f.filterRespWithRuleLists(resp, s, dns.TypeHTTPS)
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

// type check
var _ rulelist.IDMapper = (*Filter)(nil)

// Map implements the [rulelist.IDMapper] interface for *Filter.  It returns the
// rule list data by its synthetic integer ID in the urlfilter engine.  It
// panics if id is not found.
func (f *Filter) Map(id int) (fltID internal.ID, svcID internal.BlockedServiceID) {
	for _, rl := range f.ruleLists {
		if rl.URLFilterID() == id {
			return rl.ID()
		}
	}

	if rl := f.custom; rl != nil && rl.URLFilterID() == id {
		return rl.ID()
	}

	for _, rl := range f.svcLists {
		if rl.URLFilterID() == id {
			return rl.ID()
		}
	}

	// Technically shouldn't happen, since id is supposed to be among the rule
	// list filters in the composite filter.
	panic(fmt.Errorf("filter: synthetic id %d not found", id))
}
