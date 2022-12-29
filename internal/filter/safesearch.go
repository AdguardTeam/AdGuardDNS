package filter

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/resultcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/miekg/dns"
)

// Safe search

// safeSearch is a filter that enforces safe search.
type safeSearch struct {
	// resCache contains cached results.
	resCache *resultcache.Cache[*ResultModified]

	// flt is used to filter requests.
	flt *ruleListFilter

	// resolver resolves IP addresses.
	resolver agdnet.Resolver

	// errColl is used to report rare errors.
	errColl agd.ErrorCollector
}

// safeSearchConfig contains configuration for the safe search filter.
type safeSearchConfig struct {
	list     *agd.FilterList
	resolver agdnet.Resolver
	errColl  agd.ErrorCollector
	cacheDir string
	//lint:ignore U1000 TODO(a.garipov): Currently unused.  See AGDNS-398.
	ttl       time.Duration
	cacheSize int
}

// newSafeSearch returns a new safe search filter.  c must not be nil.  The
// initial refresh should be called explicitly if necessary.
func newSafeSearch(c *safeSearchConfig) (f *safeSearch) {
	return &safeSearch{
		resCache: resultcache.New[*ResultModified](c.cacheSize),
		// Don't use the rule list cache, since safeSearch already has its own.
		flt:      newRuleListFilter(c.list, c.cacheDir, 0, false),
		resolver: c.resolver,
		errColl:  c.errColl,
	}
}

// type check
var _ qtHostFilter = (*safeSearch)(nil)

// filterReq implements the qtHostFilter interface for *safeSearch.  It modifies
// the response if host matches f.
func (f *safeSearch) filterReq(
	ctx context.Context,
	ri *agd.RequestInfo,
	req *dns.Msg,
) (r Result, err error) {
	qt := ri.QType
	fam := netutil.AddrFamilyFromRRType(qt)
	if fam == netutil.AddrFamilyNone {
		return nil, nil
	}

	host := ri.Host
	cacheKey := resultcache.DefaultKey(host, qt, false)
	repHost, ok := f.safeSearchHost(host, qt)
	if !ok {
		optlog.Debug2("filter %s: host %q is not on the list", f.flt.id(), host)

		f.resCache.Set(cacheKey, nil)

		return nil, nil
	}

	optlog.Debug2("filter %s: found host %q", f.flt.id(), repHost)

	rm, ok := f.resCache.Get(cacheKey)
	if ok {
		if rm == nil {
			// Return nil explicitly instead of modifying CloneForReq to return
			// nil if the result is nil to avoid a “non-nil nil” value.
			return nil, nil
		}

		return rm.CloneForReq(req), nil
	}

	ctx, cancel := context.WithTimeout(ctx, defaultResolveTimeout)
	defer cancel()

	var result *dns.Msg
	ips, err := f.resolver.LookupIP(ctx, fam, repHost)
	if err != nil {
		agd.Collectf(ctx, f.errColl, "filter %s: resolving: %w", f.flt.id(), err)

		result = ri.Messages.NewMsgSERVFAIL(req)
	} else {
		result, err = ri.Messages.NewIPRespMsg(req, ips...)
		if err != nil {
			return nil, fmt.Errorf("filter %s: creating modified result: %w", f.flt.id(), err)
		}
	}

	rm = &ResultModified{
		Msg:  result,
		List: f.flt.id(),
		Rule: agd.FilterRuleText(host),
	}

	// Copy the result to make sure that modifications to the result message
	// down the pipeline don't interfere with the cached value.
	//
	// See AGDNS-359.
	f.resCache.Set(cacheKey, rm.Clone())

	return rm, nil
}

// safeSearchHost returns the replacement host for the given host and question
// type, if any.  qt should be either [dns.TypeA] or [dns.TypeAAAA].
func (f *safeSearch) safeSearchHost(host string, qt dnsmsg.RRType) (ssHost string, ok bool) {
	dnsReq := &urlfilter.DNSRequest{
		Hostname: host,
		DNSType:  qt,
		Answer:   false,
	}

	f.flt.mu.RLock()
	defer f.flt.mu.RUnlock()

	// Omit matching the result since it's always false for rewrite rules.
	dr, _ := f.flt.engine.MatchRequest(dnsReq)
	if dr == nil {
		return "", false
	}

	for _, nr := range dr.DNSRewrites() {
		drw := nr.DNSRewrite
		if drw.RCode != dns.RcodeSuccess {
			continue
		}

		if nc := drw.NewCNAME; nc != "" {
			return nc, true
		}

		// All the rules in safe search rule lists are expected to have either
		// A/AAAA or CNAME type.
		switch drw.RRType {
		case dns.TypeA, dns.TypeAAAA:
			return drw.Value.(net.IP).String(), true
		default:
			continue
		}
	}

	return "", false
}

// name implements the qtHostFilter interface for *safeSearch.
func (f *safeSearch) name() (n string) {
	if f == nil || f.flt == nil {
		return ""
	}

	return string(f.flt.id())
}

// refresh reloads the rule list data.  If acceptStale is true, and the cache
// file exists, the data is read from there regardless of its staleness.
func (f *safeSearch) refresh(ctx context.Context, acceptStale bool) (err error) {
	err = f.flt.refresh(ctx, acceptStale)
	if err != nil {
		return err
	}

	f.resCache.Clear()

	return nil
}
