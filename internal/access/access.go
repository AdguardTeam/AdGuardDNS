// Package access contains structures for access control management.
package access

import (
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdurlflt"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
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
	reqPool         *syncutil.Pool[urlfilter.DNSRequest]
	resPool         *syncutil.Pool[urlfilter.DNSResult]
}

// NewGlobal creates a new *Global from provided parameters.
func NewGlobal(blockedDomains []string, blockedSubnets []netip.Prefix) (g *Global, err error) {
	g = &Global{
		blockedNets: netutil.SliceSubnetSet(blockedSubnets),
		reqPool: syncutil.NewPool(func() (req *urlfilter.DNSRequest) {
			return &urlfilter.DNSRequest{}
		}),
		resPool: syncutil.NewPool(func() (v *urlfilter.DNSResult) {
			return &urlfilter.DNSResult{}
		}),
	}

	lists := []filterlist.Interface{
		filterlist.NewBytes(&filterlist.BytesConfig{
			ID:             blocklistFilterID,
			RulesText:      agdurlflt.RulesToBytesLower(blockedDomains),
			IgnoreCosmetic: true,
		}),
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
	return matchBlocked(host, qt, g.blockedHostsEng, g.reqPool, g.resPool)
}

// matchBlocked is a helper function that handles matching of request using DNS
// engines and pools of requests and results.  engine, reqPool, and resPool must
// not be nil.
func matchBlocked(
	host string,
	qt uint16,
	engine *urlfilter.DNSEngine,
	reqPool *syncutil.Pool[urlfilter.DNSRequest],
	resPool *syncutil.Pool[urlfilter.DNSResult],
) (blocked bool) {
	req := reqPool.Get()
	defer reqPool.Put(req)

	req.Reset()
	req.Hostname = host
	req.DNSType = qt

	res := resPool.Get()
	defer resPool.Put(res)

	res.Reset()

	blocked = engine.MatchRequestInto(req, res)
	if blocked && res.NetworkRule != nil {
		return !res.NetworkRule.Whitelist
	}

	return blocked
}

// IsBlockedIP implements the [Interface] interface for *Global.
func (g *Global) IsBlockedIP(ip netip.Addr) (blocked bool) {
	return g.blockedNets.Contains(ip)
}
