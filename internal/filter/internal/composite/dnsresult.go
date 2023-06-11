package composite

import (
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/rules"
)

// urlFilterResult is an entity simplifying the collection and compilation of
// urlfilter results.
//
// TODO(a.garipov): Think of ways to move all urlfilter result processing to
// ./internal/rulelist.
type urlFilterResult struct {
	networkRules []*rules.NetworkRule
	hostRules4   []*rules.HostRule
	hostRules6   []*rules.HostRule
}

// add appends the rules from dr to the slices within r.  If dr is nil, add does
// nothing.
func (r *urlFilterResult) add(dr *urlfilter.DNSResult) {
	if dr != nil {
		r.networkRules = append(r.networkRules, dr.NetworkRules...)
		r.hostRules4 = append(r.hostRules4, dr.HostRulesV4...)
		r.hostRules6 = append(r.hostRules6, dr.HostRulesV6...)
	}
}
