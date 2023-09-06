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

// unit is a convenient alias for struct{}
type unit = struct{}

// Interface is the access manager interface.
type Interface interface {
	// IsBlockedHost returns true if host should be blocked.
	IsBlockedHost(host string, qt uint16) (blocked bool)

	// IsBlockedIP returns the status of the IP address blocking as well as the
	// rule that blocked it.
	IsBlockedIP(ip netip.Addr) (blocked bool, rule string)
}

// type check
var _ Interface = (*Manager)(nil)

// Manager controls IP and client blocking that takes place before all
// other processing.  An Manager is safe for concurrent use.
type Manager struct {
	blockedIPs      map[netip.Addr]unit
	blockedHostsEng *urlfilter.DNSEngine
	blockedNets     []netip.Prefix
}

// New create an Manager.  The parameters assumed to be valid.
func New(blockedDomains, blockedSubnets []string) (am *Manager, err error) {
	am = &Manager{
		blockedIPs: map[netip.Addr]unit{},
	}

	processAccessList(blockedSubnets, am.blockedIPs, &am.blockedNets)

	b := &strings.Builder{}
	for _, h := range blockedDomains {
		stringutil.WriteToBuilder(b, strings.ToLower(h), "\n")
	}

	lists := []filterlist.RuleList{
		&filterlist.StringRuleList{
			ID:             0,
			RulesText:      b.String(),
			IgnoreCosmetic: true,
		},
	}

	rulesStrg, err := filterlist.NewRuleStorage(lists)
	if err != nil {
		return nil, fmt.Errorf("adding blocked hosts: %w", err)
	}

	am.blockedHostsEng = urlfilter.NewDNSEngine(rulesStrg)

	return am, nil
}

// processAccessList is a helper for processing a list of strings, each of them
// assumed be a valid IP address or a valid CIDR.
func processAccessList(strs []string, ips map[netip.Addr]unit, nets *[]netip.Prefix) {
	for _, s := range strs {
		var err error
		var ip netip.Addr
		var ipnet netip.Prefix
		if ip, err = netip.ParseAddr(s); err == nil {
			ips[ip] = unit{}
		} else if ipnet, err = netip.ParsePrefix(s); err == nil {
			*nets = append(*nets, ipnet)
		}
	}
}

// IsBlockedHost returns true if host should be blocked.
func (am *Manager) IsBlockedHost(host string, qt uint16) (blocked bool) {
	_, blocked = am.blockedHostsEng.MatchRequest(&urlfilter.DNSRequest{
		Hostname: host,
		DNSType:  qt,
	})

	return blocked
}

// IsBlockedIP returns the status of the IP address blocking as well as the rule
// that blocked it.
func (am *Manager) IsBlockedIP(ip netip.Addr) (blocked bool, rule string) {
	if _, ok := am.blockedIPs[ip]; ok {
		return true, ip.String()
	}

	for _, ipnet := range am.blockedNets {
		if ipnet.Contains(ip) {
			return true, ipnet.String()
		}
	}

	return false, ""
}
