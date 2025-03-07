package composite

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

// urlFilterResult is an entity simplifying the collection and compilation of
// urlfilter results.  It contains per-pointer indexes of the IDs of filters
// producing network and host rules.
type urlFilterResult struct {
	netRuleIDs  map[*rules.NetworkRule]filter.ID
	hostRuleIDs map[*rules.HostRule]filter.ID

	netRuleSvcIDs  map[*rules.NetworkRule]filter.BlockedServiceID
	hostRuleSvcIDs map[*rules.HostRule]filter.BlockedServiceID

	networkRules []*rules.NetworkRule
	hostRules4   []*rules.HostRule
	hostRules6   []*rules.HostRule
}

// newURLFilterResult returns a properly initialized *urlFilterResult.
func newURLFilterResult() (r *urlFilterResult) {
	return &urlFilterResult{
		netRuleIDs:  map[*rules.NetworkRule]filter.ID{},
		hostRuleIDs: map[*rules.HostRule]filter.ID{},

		netRuleSvcIDs:  map[*rules.NetworkRule]filter.BlockedServiceID{},
		hostRuleSvcIDs: map[*rules.HostRule]filter.BlockedServiceID{},
	}
}

// add appends the rules from dr to the slices within r.  If dr is nil, add does
// nothing.
func (r *urlFilterResult) add(
	id filter.ID,
	svcID filter.BlockedServiceID,
	dr *urlfilter.DNSResult,
) {
	if dr == nil {
		return
	}

	for _, nr := range dr.NetworkRules {
		r.networkRules = append(r.networkRules, nr)
		r.netRuleIDs[nr] = id
		if svcID != "" {
			r.netRuleSvcIDs[nr] = svcID
		}
	}

	r.addHostRules(id, svcID, dr.HostRulesV4, dr.HostRulesV6)
}

// addHostRules adds the host rules to the result.
func (r *urlFilterResult) addHostRules(
	id filter.ID,
	svcID filter.BlockedServiceID,
	hostRules4 []*rules.HostRule,
	hostRules6 []*rules.HostRule,
) {
	for _, hr4 := range hostRules4 {
		r.hostRules4 = append(r.hostRules4, hr4)
		r.hostRuleIDs[hr4] = id
		if svcID != "" {
			r.hostRuleSvcIDs[hr4] = svcID
		}
	}

	for _, hr6 := range hostRules6 {
		r.hostRules6 = append(r.hostRules6, hr6)
		r.hostRuleIDs[hr6] = id
		if svcID != "" {
			r.hostRuleSvcIDs[hr6] = svcID
		}
	}
}

// toInternal converts a result of using several urlfilter rulelists into a
// filter.Result.
func (r *urlFilterResult) toInternal(rrType dnsmsg.RRType) (res filter.Result) {
	if nr := rules.GetDNSBasicRule(r.networkRules); nr != nil {
		return r.netRuleDataToResult(nr)
	}

	return r.hostsRulesToResult(rrType)
}

// netRuleDataToResult converts a urlfilter network rule into a filtering
// result.
func (r *urlFilterResult) netRuleDataToResult(nr *rules.NetworkRule) (res filter.Result) {
	fltID, ok := r.netRuleIDs[nr]
	if !ok {
		// Shouldn't happen, since fltID is supposed to be among the filters
		// added to the result.
		panic(fmt.Errorf("composite: filter id %q not found", fltID))
	}

	var rule filter.RuleText
	if fltID == filter.IDBlockedService {
		var svcID filter.BlockedServiceID
		svcID, ok = r.netRuleSvcIDs[nr]
		if !ok {
			// Shouldn't happen, since svcID is supposed to be among the filters
			// added to the result.
			panic(fmt.Errorf("composite: service id %q not found", svcID))
		}

		rule = filter.RuleText(svcID)
	} else {
		rule = filter.RuleText(nr.RuleText)
	}

	if nr.Whitelist {
		return &filter.ResultAllowed{
			List: fltID,
			Rule: rule,
		}
	}

	return &filter.ResultBlocked{
		List: fltID,
		Rule: rule,
	}
}

// hostsRulesToResult converts /etc/hosts-style rules into a filtering result.
func (r *urlFilterResult) hostsRulesToResult(rrType dnsmsg.RRType) (res filter.Result) {
	if len(r.hostRules4) == 0 && len(r.hostRules6) == 0 {
		return nil
	}

	// Only use the first matched rule, since we currently don't care about the
	// IP addresses in the rule.  If the request is neither an A one nor an AAAA
	// one, or if there are no matching rules of the requested type, then use
	// whatever rule isn't empty.
	//
	// See also AGDNS-591.
	var resHostRule *rules.HostRule
	if rrType == dns.TypeA && len(r.hostRules4) > 0 {
		resHostRule = r.hostRules4[0]
	} else if rrType == dns.TypeAAAA && len(r.hostRules6) > 0 {
		resHostRule = r.hostRules6[0]
	} else {
		if len(r.hostRules4) > 0 {
			resHostRule = r.hostRules4[0]
		} else {
			resHostRule = r.hostRules6[0]
		}
	}

	return r.hostRuleDataToResult(resHostRule)
}

// hostRuleDataToResult converts a urlfilter host rule into a filtering result.
func (r *urlFilterResult) hostRuleDataToResult(hr *rules.HostRule) (res filter.Result) {
	fltID, ok := r.hostRuleIDs[hr]
	if !ok {
		// Shouldn't happen, since fltID is supposed to be among the filters
		// added to the result.
		panic(fmt.Errorf("composite: filter id %q not found", fltID))
	}

	var rule filter.RuleText
	if fltID == filter.IDBlockedService {
		var svcID filter.BlockedServiceID
		svcID, ok = r.hostRuleSvcIDs[hr]
		if !ok {
			// Shouldn't happen, since svcID is supposed to be among the filters
			// added to the result.
			panic(fmt.Errorf("composite: service id %q not found", svcID))
		}

		rule = filter.RuleText(svcID)
	} else {
		rule = filter.RuleText(hr.RuleText)
	}

	return &filter.ResultBlocked{
		List: fltID,
		Rule: rule,
	}
}
