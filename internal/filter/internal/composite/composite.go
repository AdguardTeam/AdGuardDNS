// Package composite implements a composite filter based on several types of
// filters and the logic of the filter application.
package composite

import (
	"context"
	"fmt"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/safesearch"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

// Filter is a composite filter based on several types of safe-search and
// rule-list filters.
//
// An empty composite filter is a filter that always returns a nil filtering
// result.
type Filter struct {
	safeBrowsing         *hashprefix.Filter
	newRegisteredDomains *hashprefix.Filter
	adultBlocking        *hashprefix.Filter

	genSafeSearch *safesearch.Filter
	ytSafeSearch  *safesearch.Filter

	// custom is the custom rule-list filter of the profile, if any.
	custom *rulelist.Immutable

	// ruleLists are the enabled rule-list filters of the profile or filtering
	// group.
	ruleLists []*rulelist.Refreshable

	// svcLists are the rule-list filters of the profile's enabled blocked
	// services, if any.
	svcLists []*rulelist.Immutable
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
	// group.
	RuleLists []*rulelist.Refreshable

	// ServiceLists are the rule-list filters of the profile's enabled blocked
	// services, if any.
	ServiceLists []*rulelist.Immutable
}

// New returns a new composite filter.  If c is nil or empty, f returns a filter
// that always returns a nil filtering result.
func New(c *Config) (f *Filter) {
	if c == nil {
		return &Filter{}
	}

	return &Filter{
		safeBrowsing:         c.SafeBrowsing,
		adultBlocking:        c.AdultBlocking,
		genSafeSearch:        c.GeneralSafeSearch,
		ytSafeSearch:         c.YouTubeSafeSearch,
		custom:               c.Custom,
		ruleLists:            c.RuleLists,
		svcLists:             c.ServiceLists,
		newRegisteredDomains: c.NewRegisteredDomains,
	}
}

// type check
var _ internal.Interface = (*Filter)(nil)

// FilterRequest implements the [internal.Interface] interface for *Filter.  If
// there is a safe-search result, it returns it.  Otherwise, it returns the
// action created from the filter list network rule with the highest priority.
// If f is empty, it returns nil with no error.
func (f *Filter) FilterRequest(
	ctx context.Context,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (r internal.Result, err error) {
	if f.isEmpty() {
		return nil, nil
	}

	// Prepare common data for filters.
	reqID := ri.ID
	log.Debug("filters: filtering req %s: %d rule lists", reqID, len(f.ruleLists))

	// Firstly, check the profile's rule-list filtering, the custom rules, and
	// the rules from blocked services settings.
	host := ri.Host
	rlRes := f.filterWithRuleLists(ri, host, ri.QType, req, false)
	switch flRes := rlRes.(type) {
	case *internal.ResultAllowed:
		// Skip any additional filtering if the domain is explicitly allowed by
		// user's custom rule.
		if flRes.List == agd.FilterListIDCustom {
			return flRes, nil
		}
	case *internal.ResultBlocked:
		// Skip any additional filtering if the domain is already blocked.
		return flRes, nil
	default:
		// Go on.
	}

	// Secondly, apply the safe browsing and safe search request filters in the
	// following order.
	//
	// DO NOT change the order of reqFilters without necessity.
	reqFilters := []struct {
		filter internal.RequestFilter
		id     agd.FilterListID
	}{{
		filter: nullify(f.safeBrowsing),
		id:     agd.FilterListIDSafeBrowsing,
	}, {
		filter: nullify(f.adultBlocking),
		id:     agd.FilterListIDAdultBlocking,
	}, {
		filter: nullify(f.genSafeSearch),
		id:     agd.FilterListIDGeneralSafeSearch,
	}, {
		filter: nullify(f.ytSafeSearch),
		id:     agd.FilterListIDYoutubeSafeSearch,
	}, {
		filter: nullify(f.newRegisteredDomains),
		id:     agd.FilterListIDNewRegDomains,
	}}

	for _, rf := range reqFilters {
		if rf.filter == nil {
			continue
		}

		log.Debug("filter %s: filtering req %s", rf.id, reqID)
		r, err = rf.filter.FilterRequest(ctx, req, ri)
		log.Debug("filter %s: finished filtering req %s, errors: %v", rf.id, reqID, err)
		if err != nil {
			return nil, err
		} else if r != nil {
			return r, nil
		}
	}

	// Thirdly, return the previously obtained filter list result.
	return rlRes, nil
}

// nullify returns a nil interface value if flt is a nil pointer.  Otherwise, it
// returns flt converted to the interface type.  It is used to avoid situations
// where an interface value doesn't have any data but does have a type.
func nullify[T *safesearch.Filter | *hashprefix.Filter](flt T) (fr internal.RequestFilter) {
	if flt == nil {
		return nil
	}

	return internal.RequestFilter(flt)
}

// FilterResponse implements the [internal.Interface] interface for *Filter.  It
// returns the action created from the filter list network rule with the highest
// priority.  If f is empty, it returns nil with no error.
func (f *Filter) FilterResponse(
	_ context.Context,
	resp *dns.Msg,
	ri *agd.RequestInfo,
) (r internal.Result, err error) {
	if f.isEmpty() {
		return nil, nil
	}

	for _, ans := range resp.Answer {
		if rr, ok := ans.(*dns.HTTPS); ok {
			r = f.filterHTTPSRecords(rr, ri, resp)
			if r != nil {
				return r, nil
			}
		}

		host, rrType, ok := parseRespAnswer(ans)
		if !ok {
			continue
		}

		r = f.filterWithRuleLists(ri, host, rrType, resp, true)
		if r != nil {
			break
		}
	}

	return r, nil
}

// filterHTTPSRecords filters HTTPS answers information through all rule list
// filters of the composite filter.
func (f *Filter) filterHTTPSRecords(
	rr *dns.HTTPS,
	ri *agd.RequestInfo,
	resp *dns.Msg,
) (r internal.Result) {
	for _, kv := range rr.Value {
		switch kv.Key() {
		case dns.SVCB_IPV4HINT, dns.SVCB_IPV6HINT:
			r = f.filterSVCBHint(kv.String(), ri, resp)
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
	hint string,
	ri *agd.RequestInfo,
	resp *dns.Msg,
) (r internal.Result) {
	for _, s := range strings.Split(hint, ",") {
		r = f.filterWithRuleLists(ri, s, dns.TypeHTTPS, resp, true)
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

// isEmpty returns true if this composite filter is an empty filter.
func (f *Filter) isEmpty() (ok bool) {
	return f == nil ||
		(f.safeBrowsing == nil &&
			f.adultBlocking == nil &&
			f.genSafeSearch == nil &&
			f.ytSafeSearch == nil &&
			f.custom == nil &&
			f.newRegisteredDomains == nil &&
			len(f.ruleLists) == 0 &&
			len(f.svcLists) == 0)
}

// filterWithRuleLists filters one question's or answer's information through
// all rule list filters of the composite filter.
func (f *Filter) filterWithRuleLists(
	ri *agd.RequestInfo,
	host string,
	rrType dnsmsg.RRType,
	msg *dns.Msg,
	isAnswer bool,
) (r internal.Result) {
	var devName string
	if d := ri.Device; d != nil {
		devName = string(d.Name)
	}

	ufRes := &urlFilterResult{}
	for _, rl := range f.ruleLists {
		ufRes.add(rl.DNSResult(ri.RemoteIP, devName, host, rrType, isAnswer))
	}

	if f.custom != nil {
		dr := f.custom.DNSResult(ri.RemoteIP, devName, host, rrType, isAnswer)
		// Collect only custom $dnsrewrite rules.  It's much easier to process
		// dnsrewrite rules only from one list, cause when there is no problem
		// with merging them among different lists.
		if !isAnswer {
			modified := processDNSRewrites(ri.Messages, msg, dr.DNSRewrites(), host)
			if modified != nil {
				return modified
			}
		}

		ufRes.add(dr)
	}

	for _, rl := range f.svcLists {
		ufRes.add(rl.DNSResult(ri.RemoteIP, devName, host, rrType, isAnswer))
	}

	mr := rules.NewMatchingResult(ufRes.networkRules, nil)
	if nr := mr.GetBasicResult(); nr != nil {
		return f.ruleDataToResult(nr.FilterListID, nr.RuleText, nr.Whitelist)
	}

	return f.hostsRulesToResult(ufRes.hostRules4, ufRes.hostRules6, rrType)
}

// mustRuleListDataByURLFilterID returns the rule list data by its synthetic
// integer ID in the urlfilter engine.  It panics if id is not found.
func (f *Filter) mustRuleListDataByURLFilterID(
	id int,
) (fltID agd.FilterListID, svcID agd.BlockedServiceID) {
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

// hostsRulesToResult converts /etc/hosts-style rules into a filtering action.
func (f *Filter) hostsRulesToResult(
	hostRules4 []*rules.HostRule,
	hostRules6 []*rules.HostRule,
	rrType dnsmsg.RRType,
) (r internal.Result) {
	if len(hostRules4) == 0 && len(hostRules6) == 0 {
		return nil
	}

	// Only use the first matched rule, since we currently don't care about the
	// IP addresses in the rule.  If the request is neither an A one nor an AAAA
	// one, or if there are no matching rules of the requested type, then use
	// whatever rule isn't empty.
	//
	// See also AGDNS-591.
	var resHostRule *rules.HostRule
	if rrType == dns.TypeA && len(hostRules4) > 0 {
		resHostRule = hostRules4[0]
	} else if rrType == dns.TypeAAAA && len(hostRules6) > 0 {
		resHostRule = hostRules6[0]
	} else {
		if len(hostRules4) > 0 {
			resHostRule = hostRules4[0]
		} else {
			resHostRule = hostRules6[0]
		}
	}

	return f.ruleDataToResult(resHostRule.FilterListID, resHostRule.RuleText, false)
}

// ruleDataToResult converts a urlfilter rule data into a filtering result.
func (f *Filter) ruleDataToResult(
	urlFilterID int,
	ruleText string,
	allowlist bool,
) (r internal.Result) {
	// Use the urlFilterID crutch to find the actual IDs of the filtering rule
	// list and blocked service.
	fltID, svcID := f.mustRuleListDataByURLFilterID(urlFilterID)

	var rule agd.FilterRuleText
	if fltID == agd.FilterListIDBlockedService {
		rule = agd.FilterRuleText(svcID)
	} else {
		rule = agd.FilterRuleText(ruleText)
	}

	if allowlist {
		log.Debug("rule list %s: allowed by rule %s", fltID, rule)

		return &internal.ResultAllowed{
			List: fltID,
			Rule: rule,
		}
	}

	log.Debug("rule list %s: blocked by rule %s", fltID, rule)

	return &internal.ResultBlocked{
		List: fltID,
		Rule: rule,
	}
}
