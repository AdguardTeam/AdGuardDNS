package filter

import (
	"context"
	"fmt"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

// Composite Filter

// type check
var _ Interface = (*compFilter)(nil)

// compFilter is a composite filter based on several types of safe search
// filters and rule lists.
type compFilter struct {
	safeBrowsing  *hashPrefixFilter
	adultBlocking *hashPrefixFilter

	genSafeSearch *safeSearch
	ytSafeSearch  *safeSearch

	ruleLists []*ruleListFilter
}

// qtHostFilter is a filter that can filter a request based on its query type
// and host.
//
// TODO(a.garipov): See if devirtualizing this interface would give us any
// considerable performance gains.
type qtHostFilter interface {
	filterReq(
		ctx context.Context,
		ri *agd.RequestInfo,
		req *dns.Msg,
	) (r Result, err error)
	name() (n string)
}

// FilterRequest implements the Interface interface for *compFilter.  If there
// is a safe search result, it returns it.  Otherwise, it returns the action
// created from the filter list network rule with the highest priority.  If f is
// empty, it returns nil with no error.
func (f *compFilter) FilterRequest(
	ctx context.Context,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (r Result, err error) {
	if f.isEmpty() {
		return nil, nil
	}

	// Prepare common data for filters.
	reqID := ri.ID
	log.Debug("filters: filtering req %s: %d rule lists", reqID, len(f.ruleLists))

	// Firstly, check the profile's filter list rules, custom rules, and the
	// rules from blocked services settings.
	host := ri.Host
	flRes := f.filterMsg(ri, host, ri.QType, req, false)
	switch flRes := flRes.(type) {
	case *ResultAllowed:
		// Skip any additional filtering if the domain is explicitly allowed by
		// user's custom rule.
		if flRes.List == agd.FilterListIDCustom {
			return flRes, nil
		}
	case *ResultBlocked:
		// Skip any additional filtering if the domain is already blocked.
		return flRes, nil
	default:
		// Go on.
	}

	// Secondly, apply the safe browsing and safe search filters in the
	// following order.
	//
	// DO NOT change the order of filters without necessity.
	filters := []qtHostFilter{
		f.safeBrowsing,
		f.adultBlocking,
		f.genSafeSearch,
		f.ytSafeSearch,
	}

	for _, flt := range filters {
		name := flt.name()
		if name == "" {
			// A nil filter, skip.
			continue
		}

		log.Debug("filter %s: filtering req %s", name, reqID)
		r, err = flt.filterReq(ctx, ri, req)
		log.Debug("filter %s: finished filtering req %s, errors: %v", name, reqID, err)
		if err != nil {
			return nil, err
		} else if r != nil {
			return r, nil
		}
	}

	// Thirdly, return the previously obtained filter list result.
	return flRes, nil
}

// FilterResponse implements the Interface interface for *compFilter.  It
// returns the action created from the filter list network rule with the highest
// priority.  If f is empty, it returns nil with no error.
func (f *compFilter) FilterResponse(
	ctx context.Context,
	resp *dns.Msg,
	ri *agd.RequestInfo,
) (r Result, err error) {
	if f.isEmpty() || len(resp.Answer) == 0 {
		return nil, nil
	}

	for _, ans := range resp.Answer {
		host, rrType, ok := parseRespAnswer(ans)
		if !ok {
			continue
		}

		r = f.filterMsg(ri, host, rrType, resp, true)
		if r != nil {
			break
		}
	}

	return r, nil
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
func (f *compFilter) isEmpty() (ok bool) {
	return f == nil || (f.safeBrowsing == nil &&
		f.adultBlocking == nil &&
		f.genSafeSearch == nil &&
		f.ytSafeSearch == nil &&
		len(f.ruleLists) == 0)
}

// filterMsg filters one question's or answer's information through all rule
// list filters of the composite filter.
func (f *compFilter) filterMsg(
	ri *agd.RequestInfo,
	host string,
	rrType dnsmsg.RRType,
	msg *dns.Msg,
	answer bool,
) (r Result) {
	var devName agd.DeviceName
	if d := ri.Device; d != nil {
		devName = d.Name
	}

	var networkRules []*rules.NetworkRule
	var hostRules4 []*rules.HostRule
	var hostRules6 []*rules.HostRule
	for _, rl := range f.ruleLists {
		dr := rl.dnsResult(ri.RemoteIP, string(devName), host, rrType, answer)
		if dr == nil {
			continue
		}

		// Collect only custom $dnsrewrite rules.  It's much more easy
		// to process dnsrewrite rules only from one list, cause when
		// there is no problem with merging them among different lists.
		if !answer && rl.id() == agd.FilterListIDCustom {
			dnsRewriteResult := processDNSRewrites(ri.Messages, msg, dr.DNSRewrites(), host)
			if dnsRewriteResult != nil {
				dnsRewriteResult.List = rl.id()

				return dnsRewriteResult
			}
		}

		networkRules = append(networkRules, dr.NetworkRules...)
		hostRules4 = append(hostRules4, dr.HostRulesV4...)
		hostRules6 = append(hostRules6, dr.HostRulesV6...)
	}

	mr := rules.NewMatchingResult(networkRules, nil)
	if nr := mr.GetBasicResult(); nr != nil {
		return f.ruleDataToResult(nr.FilterListID, nr.RuleText, nr.Whitelist)
	}

	return f.hostsRulesToResult(hostRules4, hostRules6, rrType)
}

// mustRuleListDataByURLFilterID returns the rule list data by its synthetic
// integer ID in the urlfilter engine.  It panics if id is not found.
func (f *compFilter) mustRuleListDataByURLFilterID(
	id int,
) (fltID agd.FilterListID, svcID agd.BlockedServiceID) {
	for _, rl := range f.ruleLists {
		if rl.urlFilterID == id {
			return rl.id(), rl.svcID
		}
	}

	// Technically shouldn't happen, since id is supposed to be among the rule
	// list filters in the composite filter.
	panic(fmt.Errorf("filter: synthetic id %d not found", id))
}

// hostsRulesToResult converts /etc/hosts-style rules into a filtering action.
func (f *compFilter) hostsRulesToResult(
	hostRules4 []*rules.HostRule,
	hostRules6 []*rules.HostRule,
	rrType dnsmsg.RRType,
) (r Result) {
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

// networkRuleToResult converts a urlfilter rule data into a filtering result.
func (f *compFilter) ruleDataToResult(
	urlFilterID int,
	ruleText string,
	allowlist bool,
) (r Result) {
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

		return &ResultAllowed{
			List: fltID,
			Rule: rule,
		}
	}

	log.Debug("rule list %s: blocked by rule %s", fltID, rule)

	return &ResultBlocked{
		List: fltID,
		Rule: rule,
	}
}

// Close implements the Filter interface for *compFilter.  It closes all
// underlying filters.
func (f *compFilter) Close() (err error) {
	if f.isEmpty() {
		return nil
	}

	var errs []error
	for i, rl := range f.ruleLists {
		err = rl.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("rule list at index %d: %w", i, err))
		}
	}

	if len(errs) > 0 {
		return errors.List("closing filters", errs...)
	}

	return nil
}
