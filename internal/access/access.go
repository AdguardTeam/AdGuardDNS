// Package access contains structures for access control management.
package access

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/stringutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
)

// blocklistFilterID ia the ID for the urlfilter rule list to use in the
// internal access engines.  As there is only one rule list in the engine it
// could simply be 0.
const blocklistFilterID = 0

// Interface is the access manager interface.
type Interface interface {
	// IsBlockedHost returns true if host should be blocked.
	IsBlockedHost(host string, qt uint16) (blocked bool)

	// IsBlockedIP returns the status of the IP address blocking as well as the
	// rule that blocked it.
	IsBlockedIP(ip netip.Addr) (blocked bool)
}

// Global controls IP and client blocking that takes place before all other
// processing.  Global is safe for concurrent use.
type Global struct {
	blockedHostsEng *urlfilter.DNSEngine
	blockedNets     netutil.SubnetSet
}

// NewGlobal create a new Global from provided parameters.
func NewGlobal(blockedDomains []string, blockedSubnets []netip.Prefix) (g *Global, err error) {
	g = &Global{
		blockedNets: netutil.SliceSubnetSet(blockedSubnets),
	}

	b := &strings.Builder{}
	for _, h := range blockedDomains {
		stringutil.WriteToBuilder(b, strings.ToLower(h), "\n")
	}

	lists := []filterlist.RuleList{
		&filterlist.StringRuleList{
			ID:             blocklistFilterID,
			RulesText:      b.String(),
			IgnoreCosmetic: true,
		},
	}

	rulesStrg, err := filterlist.NewRuleStorage(lists)
	if err != nil {
		return nil, fmt.Errorf("adding blocked hosts: %w", err)
	}

	g.blockedHostsEng = urlfilter.NewDNSEngine(rulesStrg)

	return g, nil
}

// type check
var _ Interface = (*Global)(nil)

// IsBlockedHost implements the [Interface] interface for *Global.
func (g *Global) IsBlockedHost(host string, qt uint16) (blocked bool) {
	res, matched := g.blockedHostsEng.MatchRequest(&urlfilter.DNSRequest{
		Hostname: host,
		DNSType:  qt,
	})

	if matched && res.NetworkRule != nil {
		return !res.NetworkRule.Whitelist
	}

	return matched
}

// IsBlockedIP implements the [Interface] interface for *Global.
func (g *Global) IsBlockedIP(ip netip.Addr) (blocked bool) {
	return g.blockedNets.Contains(ip)
}
