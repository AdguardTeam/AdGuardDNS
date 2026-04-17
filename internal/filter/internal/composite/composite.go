// Package composite implements a composite filter based on several types of
// filters and the logic of the filter application.
package composite

import (
	"context"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/urlfilter"
	"github.com/miekg/dns"
)

// Filter is a composite filter based on several types of safe-search and
// rule-list filters.
type Filter struct {
	// ufReq is the URLFilter request data to use and reuse during filtering.
	ufReq *urlfilter.DNSRequest

	// ufRes is the URLFilter result data to use and reuse during filtering.
	ufRes *urlfilter.DNSResult

	// custom is the custom rule-list filter of the profile, if any.
	custom filter.Custom

	// ruleLists are the enabled rule-list filters of the profile or filtering
	// group.
	ruleLists []*rulelist.Refreshable

	// customRuleLists are the enabled custom rule-list filters of the profile.
	customRuleLists []*rulelist.Refreshable

	// svcLists are the rule-list filters of the profile's enabled blocked
	// services, if any.
	svcLists []*rulelist.Immutable

	// reqFilters are the safe-browsing request filters in the composite filter.
	reqFilters []RequestFilter
}

// Config is the configuration structure for the composite filter.
type Config struct {
	// URLFilterRequest is the request data to use and reuse during filtering.
	// It must not be nil.
	URLFilterRequest *urlfilter.DNSRequest

	// URLFilterResult is the result data to use and reuse during filtering.  It
	// must not be nil.
	URLFilterResult *urlfilter.DNSResult

	// SafeBrowsing is the safe-browsing filter to apply, if any.
	SafeBrowsing RequestFilter

	// AdultBlocking is the adult-content filter to apply, if any.
	AdultBlocking RequestFilter

	// NewRegisteredDomains is the newly registered domains filter to apply, if
	// any.
	NewRegisteredDomains RequestFilter

	// Typosquatting is a typosquatting filter based on Damerau–Levenshtein
	// distance, if any.
	Typosquatting RequestFilter

	// GeneralSafeSearch is the general safe-search filter to apply, if any.
	GeneralSafeSearch RequestFilterUF

	// YouTubeSafeSearch is the youtube safe-search filter to apply, if any.
	YouTubeSafeSearch RequestFilterUF

	// Custom is the custom rule-list filter of the profile, if any.
	Custom filter.Custom

	// CategoryFilters are the enabled category request filters of the profile.
	CategoryFilters []RequestFilter

	// CustomRuleLists are the enabled custom rule-list filters of the profile.
	CustomRuleLists []*rulelist.Refreshable

	// RuleLists are the enabled rule-list filters of the profile or filtering
	// group, if any.  All items must not be nil.
	RuleLists []*rulelist.Refreshable

	// ServiceLists are the rule-list filters of the profile's enabled blocked
	// services, if any.  All items must not be nil.
	ServiceLists []*rulelist.Immutable
}

// New returns a new composite filter.  c must not be nil.
//
// TODO(a.garipov):  Consider reusing composite filters and adding function Set
// and method Reset.
func New(c *Config) (f *Filter) {
	f = &Filter{
		ufReq:           c.URLFilterRequest,
		ufRes:           c.URLFilterResult,
		custom:          c.Custom,
		customRuleLists: c.CustomRuleLists,
		ruleLists:       c.RuleLists,
		svcLists:        c.ServiceLists,
	}

	// DO NOT change the order of request filters without necessity.
	f.reqFilters = appendIfNotNil(f.reqFilters, c.SafeBrowsing)
	f.reqFilters = appendIfNotNil(f.reqFilters, c.AdultBlocking)
	f.reqFilters = appendIfNotNilUF(f.reqFilters, c.GeneralSafeSearch, f.ufReq, f.ufRes)
	f.reqFilters = appendIfNotNilUF(f.reqFilters, c.YouTubeSafeSearch, f.ufReq, f.ufRes)
	f.reqFilters = appendIfNotNil(f.reqFilters, c.NewRegisteredDomains)

	for _, df := range c.CategoryFilters {
		f.reqFilters = appendIfNotNil(f.reqFilters, df)
	}

	f.reqFilters = appendIfNotNil(f.reqFilters, c.Typosquatting)

	return f
}

// appendIfNotNil appends flt to orig if flt is not nil.
func appendIfNotNil(orig []RequestFilter, flt RequestFilter) (flts []RequestFilter) {
	flts = orig

	if flt != nil {
		flts = append(flts, flt)
	}

	return flts
}

// appendIfNotNilUF wraps flt and appends it to orig if flt is not nil.
func appendIfNotNilUF(
	orig []RequestFilter,
	flt RequestFilterUF,
	req *urlfilter.DNSRequest,
	res *urlfilter.DNSResult,
) (flts []RequestFilter) {
	flts = orig

	if flt != nil {
		// TODO(a.garipov):  Consider reusing wrapper structures.
		flts = append(flts, &ufRequestFilter{
			flt: flt,
			req: req,
			res: res,
		})
	}

	return flts
}

// type check
var _ filter.Interface = (*Filter)(nil)

// FilterRequest implements the [filter.Interface] interface for *Filter.  The
// order in which the filters are applied is the following:
//
//  1. Custom filtering rules.
//  2. Custom rule-list filters.
//  3. Common rule-list filters.
//  4. Blocked-service filters.
//  5. Dangerous-domains filter.
//  6. Adult-content filter.
//  7. General safe-search filter.
//  8. YouTube safe-search filter.
//  9. Newly-registered domains filter.
//  10. Category filters.
//  11. Typosquatting filter.
//
// If f is empty, it returns nil with no error.
func (f *Filter) FilterRequest(
	ctx context.Context,
	req *filter.Request,
) (r filter.Result, err error) {
	// Prepare common data for filters.  Firstly, check the profile's rule-list
	// filtering, the custom rules, and the rules from blocked services
	// settings.
	rlRes, fromCustom := f.filterReqWithRuleLists(ctx, req)
	switch flRes := rlRes.(type) {
	case *filter.ResultAllowed:
		// Skip any additional filtering if the domain is explicitly allowed by
		// user's custom rule or rule list.  Allowed results from common rule
		// lists and blocked services should wait until all request filters are
		// checked, since those can still block the same domains.
		if fromCustom {
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

	// Secondly, check the safe-browsing and safe-search filters.
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
) (r filter.Result, fromCustom bool) {
	f.ufReq.Reset()

	f.ufReq.ClientIP = req.RemoteIP
	// TODO(f.setrakov): Reuse client identifiers sets.
	addClientID(f.ufReq, req.ClientName)
	f.ufReq.DNSType = req.QType
	f.ufReq.Hostname = req.Host

	c := newURLFilterResultCollector()
	r = f.filterReqWithCustomFilter(ctx, req, c)
	if r != nil {
		// Custom rules have priority over all other rule lists.
		return r, true
	}

	r = f.filterReqWithCustomRuleLists(ctx, req, c)
	if r != nil {
		// Custom rule lists have priority over the common rule lists.
		return r, true
	}

	// Don't use the device name for non-custom filters.
	f.ufReq.ClientIdentifiers.Clear()

	mod := f.filterReqWithCommonRuleLists(ctx, req, c)
	if mod != nil {
		// DNS rewrites from custom rule lists have priority over other rules.
		return mod, false
	}

	for _, rl := range f.svcLists {
		id, svcID := rl.ID()

		f.ufRes.Reset()
		ok := rl.SetURLFilterResult(ctx, f.ufReq, f.ufRes)
		if ok {
			c.add(id, svcID, f.ufRes)
		}
	}

	return c.toInternal(req.QType), false
}

// addClientID adds id to req.ClientIdentifiers, initializing the set if
// necessary.  req must not be nil.
func addClientID(req *urlfilter.DNSRequest, id string) {
	if id == "" {
		return
	}

	if req.ClientIdentifiers == nil {
		req.ClientIdentifiers = container.NewSortedSliceSet(id)

		return
	}

	req.ClientIdentifiers.Add(id)
}

// filterReqWithCustomFilter filters one question's information through the
// custom-rules filter of the composite filter, if there is one.  All arguments
// must not be nil.
func (f *Filter) filterReqWithCustomFilter(
	ctx context.Context,
	req *filter.Request,
	c *urlFilterResultCollector,
) (r filter.Result) {
	if f.custom == nil {
		return nil
	}

	// Only use the device name for custom filters of profiles with devices.
	addClientID(f.ufReq, req.ClientName)

	f.ufRes.Reset()

	ok := f.custom.SetURLFilterResult(ctx, f.ufReq, f.ufRes)
	if !ok {
		return nil
	}

	id := filter.IDCustom
	r = rulelist.ProcessDNSRewrites(req, f.ufRes.DNSRewrites(), id)
	if r != nil {
		return r
	}

	c.add(id, "", f.ufRes)

	return c.toInternal(req.QType)
}

// filterReqWithCustomRuleLists filters the request through all custom rule-list
// filters of the composite filter, if there are any.  All arguments must not be
// nil.
func (f *Filter) filterReqWithCustomRuleLists(
	ctx context.Context,
	req *filter.Request,
	c *urlFilterResultCollector,
) (r filter.Result) {
	// Only use the device name for custom filters of profiles with devices.
	addClientID(f.ufReq, req.ClientName)

	for _, rl := range f.customRuleLists {
		f.ufRes.Reset()
		ok := rl.SetURLFilterResult(ctx, f.ufReq, f.ufRes)
		if !ok {
			continue
		}

		id, _ := rl.ID()

		// TODO(a.garipov):  See if DNS rewrites from multiple rule lists must
		// be merged together.
		r = rulelist.ProcessDNSRewrites(req, f.ufRes.DNSRewrites(), id)
		if r != nil {
			// DNS rewrites have higher priority, so a modified request must be
			// returned immediately.
			return r
		}

		c.add(id, "", f.ufRes)
	}

	return c.toInternal(req.QType)
}

// filterReqWithCommonRuleLists filters the request through all common rule-list
// filters of the composite filter, if there are any.  All arguments must not be
// nil.
func (f *Filter) filterReqWithCommonRuleLists(
	ctx context.Context,
	req *filter.Request,
	c *urlFilterResultCollector,
) (mod filter.Result) {
	for _, rl := range f.ruleLists {
		f.ufRes.Reset()
		ok := rl.SetURLFilterResult(ctx, f.ufReq, f.ufRes)
		if !ok {
			continue
		}

		id, _ := rl.ID()

		mod = rulelist.ProcessDNSRewrites(req, f.ufRes.DNSRewrites(), id)
		if mod != nil {
			// DNS rewrites have higher priority, so a modified request must be
			// returned immediately.
			return mod
		}

		c.add(id, "", f.ufRes)
	}

	return nil
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
	f.ufReq.Reset()

	f.ufReq.Answer = true
	f.ufReq.ClientIP = resp.RemoteIP
	f.ufReq.DNSType = rrType
	f.ufReq.Hostname = host

	c := newURLFilterResultCollector()
	if f.custom != nil {
		addClientID(f.ufReq, resp.ClientName)

		f.ufRes.Reset()

		ok := f.custom.SetURLFilterResult(ctx, f.ufReq, f.ufRes)
		if ok {
			c.add(filter.IDCustom, "", f.ufRes)

			return c.toInternal(rrType)
		}
	}

	r = f.filterRespWithCustomRuleLists(ctx, resp, c, rrType)
	if r != nil {
		return r
	}

	f.ufReq.ClientIdentifiers.Clear()

	f.filterRespWithCommonRuleLists(ctx, c)

	for _, rl := range f.svcLists {
		id, svcID := rl.ID()

		f.ufRes.Reset()
		ok := rl.SetURLFilterResult(ctx, f.ufReq, f.ufRes)
		if ok {
			c.add(id, svcID, f.ufRes)
		}
	}

	return c.toInternal(rrType)
}

// filterRespWithCustomRuleLists filters one answer's information through the
// custom rule lists of the composite filter, if there are any.  All arguments
// must not be nil.
func (f *Filter) filterRespWithCustomRuleLists(
	ctx context.Context,
	resp *filter.Response,
	c *urlFilterResultCollector,
	rrType dnsmsg.RRType,
) (r filter.Result) {
	// Only use the device name for custom filters of profiles with devices.
	addClientID(f.ufReq, resp.ClientName)

	for _, rl := range f.customRuleLists {
		id, _ := rl.ID()

		f.ufRes.Reset()

		ok := rl.SetURLFilterResult(ctx, f.ufReq, f.ufRes)
		if ok {
			c.add(id, "", f.ufRes)
		}
	}

	return c.toInternal(rrType)
}

// filterRespWithCommonRuleLists filters one answer's information through the
// common rule lists of the composite filter, if there are any.  All arguments
// must not be nil.
func (f *Filter) filterRespWithCommonRuleLists(
	ctx context.Context,
	c *urlFilterResultCollector,
) {
	for _, rl := range f.ruleLists {
		id, _ := rl.ID()

		f.ufRes.Reset()

		ok := rl.SetURLFilterResult(ctx, f.ufReq, f.ufRes)
		if ok {
			c.add(id, "", f.ufRes)
		}
	}
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
	for s := range strings.SplitSeq(hint, ",") {
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
