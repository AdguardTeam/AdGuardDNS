package composite

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

// urlFilterResultCollector is an entity simplifying the collection and
// compilation of urlfilter results.  It contains per-pointer indexes of the IDs
// of filters producing network and host rules.
//
// TODO(a.garipov):  Reuse these structures.
type urlFilterResultCollector struct {
	netRuleIDs  map[*rules.NetworkRule]filter.ID
	hostRuleIDs map[*rules.HostRule]filter.ID

	netRuleSvcIDs  map[*rules.NetworkRule]filter.BlockedServiceID
	hostRuleSvcIDs map[*rules.HostRule]filter.BlockedServiceID

	networkRules []*rules.NetworkRule
	hostRules4   []*rules.HostRule
	hostRules6   []*rules.HostRule
}

// newURLFilterResultCollector returns a properly initialized *urlFilterResult.
func newURLFilterResultCollector() (r *urlFilterResultCollector) {
	return &urlFilterResultCollector{
		netRuleIDs:  map[*rules.NetworkRule]filter.ID{},
		hostRuleIDs: map[*rules.HostRule]filter.ID{},

		netRuleSvcIDs:  map[*rules.NetworkRule]filter.BlockedServiceID{},
		hostRuleSvcIDs: map[*rules.HostRule]filter.BlockedServiceID{},
	}
}

// add appends the rules from dr to the slices within c.  dr must not be nil.
func (c *urlFilterResultCollector) add(
	id filter.ID,
	svcID filter.BlockedServiceID,
	dr *urlfilter.DNSResult,
) {
	for _, nr := range dr.NetworkRules {
		c.networkRules = append(c.networkRules, nr)
		c.netRuleIDs[nr] = id
		if svcID != "" {
			c.netRuleSvcIDs[nr] = svcID
		}
	}

	c.addHostRules(id, svcID, dr.HostRulesV4, dr.HostRulesV6)
}

// addHostRules adds the host rules to the result.
func (c *urlFilterResultCollector) addHostRules(
	id filter.ID,
	svcID filter.BlockedServiceID,
	hostRules4 []*rules.HostRule,
	hostRules6 []*rules.HostRule,
) {
	for _, hr4 := range hostRules4 {
		c.hostRules4 = append(c.hostRules4, hr4)
		c.hostRuleIDs[hr4] = id
		if svcID != "" {
			c.hostRuleSvcIDs[hr4] = svcID
		}
	}

	for _, hr6 := range hostRules6 {
		c.hostRules6 = append(c.hostRules6, hr6)
		c.hostRuleIDs[hr6] = id
		if svcID != "" {
			c.hostRuleSvcIDs[hr6] = svcID
		}
	}
}

// toInternal converts a result of using several urlfilter rulelists into a
// filter.Result.
func (c *urlFilterResultCollector) toInternal(rrType dnsmsg.RRType) (res filter.Result) {
	if nr := rules.GetDNSBasicRule(c.networkRules); nr != nil {
		return c.netRuleDataToResult(nr)
	}

	return c.hostsRulesToResult(rrType)
}

// netRuleDataToResult converts a urlfilter network rule into a filtering
// result.
func (c *urlFilterResultCollector) netRuleDataToResult(nr *rules.NetworkRule) (res filter.Result) {
	fltID, ok := c.netRuleIDs[nr]
	if !ok {
		// Shouldn't happen, since fltID is supposed to be among the filters
		// added to the result.
		panic(fmt.Errorf("composite: filter id %q not found", fltID))
	}

	var rule filter.RuleText
	if fltID == filter.IDBlockedService {
		var svcID filter.BlockedServiceID
		svcID, ok = c.netRuleSvcIDs[nr]
		if !ok {
			// Shouldn't happen, since svcID is supposed to be among the filters
			// added to the result.
			panic(fmt.Errorf("composite: service id %q not found", svcID))
		}

		rule = filter.RuleText(svcID)
	} else {
		rule = filter.RuleText(nr.Text())
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
func (c *urlFilterResultCollector) hostsRulesToResult(rrType dnsmsg.RRType) (res filter.Result) {
	if len(c.hostRules4) == 0 && len(c.hostRules6) == 0 {
		return nil
	}

	// Only use the first matched rule, since we currently don't care about the
	// IP addresses in the rule.  If the request is neither an A one nor an AAAA
	// one, or if there are no matching rules of the requested type, then use
	// whatever rule isn't empty.
	//
	// See also AGDNS-591.
	var resHostRule *rules.HostRule
	if rrType == dns.TypeA && len(c.hostRules4) > 0 {
		resHostRule = c.hostRules4[0]
	} else if rrType == dns.TypeAAAA && len(c.hostRules6) > 0 {
		resHostRule = c.hostRules6[0]
	} else {
		if len(c.hostRules4) > 0 {
			resHostRule = c.hostRules4[0]
		} else {
			resHostRule = c.hostRules6[0]
		}
	}

	return c.hostRuleDataToResult(resHostRule)
}

// hostRuleDataToResult converts a urlfilter host rule into a filtering result.
func (c *urlFilterResultCollector) hostRuleDataToResult(hr *rules.HostRule) (res filter.Result) {
	fltID, ok := c.hostRuleIDs[hr]
	if !ok {
		// Shouldn't happen, since fltID is supposed to be among the filters
		// added to the result.
		panic(fmt.Errorf("composite: filter id %q not found", fltID))
	}

	var rule filter.RuleText
	if fltID == filter.IDBlockedService {
		var svcID filter.BlockedServiceID
		svcID, ok = c.hostRuleSvcIDs[hr]
		if !ok {
			// Shouldn't happen, since svcID is supposed to be among the filters
			// added to the result.
			panic(fmt.Errorf("composite: service id %q not found", svcID))
		}

		rule = filter.RuleText(svcID)
	} else {
		rule = filter.RuleText(hr.Text())
	}

	return &filter.ResultBlocked{
		List: fltID,
		Rule: rule,
	}
}
