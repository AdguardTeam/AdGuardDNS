// Package access contains structures for access control management.
package access

import (
	"fmt"
	"net/netip"
	"strings"

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
	IsBlockedIP(ip netip.Addr) (blocked bool, rule string)
}

// Global controls IP and client blocking that takes place before all other
// processing.  Global is safe for concurrent use.
type Global struct {
	blockedIPs      map[netip.Addr]string
	blockedHostsEng *urlfilter.DNSEngine
	blockedNets     []netip.Prefix
}

// NewGlobal create a new Global from provided parameters.
func NewGlobal(blockedDomains, blockedSubnets []string) (g *Global, err error) {
	g = &Global{
		blockedIPs: map[netip.Addr]string{},
	}

	err = processAccessList(blockedSubnets, g.blockedIPs, &g.blockedNets)
	if err != nil {
		return nil, fmt.Errorf("adding blocked hosts: %w", err)
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

// processAccessList is a helper for processing a list of strings, each of them
// could be an IP address or a CIDR.
func processAccessList(strs []string, ips map[netip.Addr]string, nets *[]netip.Prefix) (err error) {
	for _, s := range strs {
		var ip netip.Addr
		var ipnet netip.Prefix
		if ip, err = netip.ParseAddr(s); err == nil {
			ips[ip] = ip.String()
		} else if ipnet, err = netip.ParsePrefix(s); err == nil {
			*nets = append(*nets, ipnet)
		} else {
			return fmt.Errorf("cannot parse subnet or ip address: %q", s)
		}
	}

	return nil
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
func (g *Global) IsBlockedIP(ip netip.Addr) (blocked bool, rule string) {
	if ipStr, ok := g.blockedIPs[ip]; ok {
		return true, ipStr
	}

	for _, ipnet := range g.blockedNets {
		if ipnet.Contains(ip) {
			return true, ipnet.String()
		}
	}

	return false, ""
}
