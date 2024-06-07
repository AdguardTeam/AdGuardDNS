package rulelist

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

// URLFilterResult is an entity simplifying the collection and compilation of
// urlfilter results.
type URLFilterResult struct {
	networkRules []*rules.NetworkRule
	hostRules4   []*rules.HostRule
	hostRules6   []*rules.HostRule
}

// Add appends the rules from dr to the slices within r.  If dr is nil, Add does
// nothing.
func (r *URLFilterResult) Add(dr *urlfilter.DNSResult) {
	if dr != nil {
		r.networkRules = append(r.networkRules, dr.NetworkRules...)
		r.hostRules4 = append(r.hostRules4, dr.HostRulesV4...)
		r.hostRules6 = append(r.hostRules6, dr.HostRulesV6...)
	}
}

// ToInternal converts a result of using several urlfilter rulelists into an
// internal.Result.
func (r *URLFilterResult) ToInternal(m IDMapper, rrType dnsmsg.RRType) (res internal.Result) {
	if nr := rules.GetDNSBasicRule(r.networkRules); nr != nil {
		return ruleDataToResult(m, nr.FilterListID, nr.RuleText, nr.Whitelist)
	}

	return r.hostsRulesToResult(m, rrType)
}

// IDMapper maps an internal urlfilter ID to AdGuard DNS IDs.
type IDMapper interface {
	Map(ufID int) (id agd.FilterListID, svcID agd.BlockedServiceID)
}

// hostsRulesToResult converts /etc/hosts-style rules into a filtering result.
func (r *URLFilterResult) hostsRulesToResult(m IDMapper, rrType dnsmsg.RRType) (res internal.Result) {
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

	return ruleDataToResult(m, resHostRule.FilterListID, resHostRule.RuleText, false)
}

// ruleDataToResult converts a urlfilter rule data into a filtering result.
func ruleDataToResult(m IDMapper, ufID int, ruleText string, isAllowlist bool) (r internal.Result) {
	fltID, svcID := m.Map(ufID)

	var rule agd.FilterRuleText
	if fltID == agd.FilterListIDBlockedService {
		rule = agd.FilterRuleText(svcID)
	} else {
		rule = agd.FilterRuleText(ruleText)
	}

	if isAllowlist {
		return &internal.ResultAllowed{
			List: fltID,
			Rule: rule,
		}
	}

	return &internal.ResultBlocked{
		List: fltID,
		Rule: rule,
	}
}
