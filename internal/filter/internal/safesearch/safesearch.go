// Package safesearch contains the implementation of the safe-search filter
// that uses lists of DNS rewrite rules to enforce safe search.
package safesearch

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/resultcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// Filter modifies the results of queries to search-engine addresses and
// rewrites them to the IP addresses of their safe versions.
type Filter struct {
	cloner   *dnsmsg.Cloner
	resCache *resultcache.Cache[*internal.ResultModified]
	flt      *rulelist.Refreshable
	resolver agdnet.Resolver
	errColl  errcoll.Interface
	id       agd.FilterListID
}

// Config contains configuration for the safe-search filter.
type Config struct {
	// Cloner is used to clone messages taken from filtering-result cache.
	Cloner *dnsmsg.Cloner

	// Refreshable is the configuration of the refreshable filter-list within
	// the safe-search filter.
	Refreshable *internal.RefreshableConfig

	// Resolver is used to resolve the IP addresses of replacement hosts.
	Resolver agdnet.Resolver

	// ErrColl is used to report errors of replacement-host resolving.
	ErrColl errcoll.Interface

	// CacheTTL is the time to live of the result cache-items.
	//
	//lint:ignore U1000 TODO(a.garipov): Currently unused.  See AGDNS-398.
	CacheTTL time.Duration

	// CacheSize is the number of items in the result cache.
	CacheSize int
}

// New returns a new safe-search filter.  c must not be nil.  The initial
// refresh should be called explicitly if necessary.
func New(c *Config) (f *Filter) {
	return &Filter{
		cloner:   c.Cloner,
		resCache: resultcache.New[*internal.ResultModified](c.CacheSize),
		// Don't use the rule list cache, since safeSearch already has its own.
		flt:      rulelist.NewRefreshable(c.Refreshable, 0, false),
		resolver: c.Resolver,
		errColl:  c.ErrColl,
		id:       c.Refreshable.ID,
	}
}

// type check
var _ internal.RequestFilter = (*Filter)(nil)

// FilterRequest implements the [internal.RequestFilter] interface for *Filter.
// It modifies the response if host matches f.
func (f *Filter) FilterRequest(
	ctx context.Context,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (r internal.Result, err error) {
	qt := ri.QType
	fam := netutil.AddrFamilyFromRRType(qt)
	if fam == netutil.AddrFamilyNone {
		return nil, nil
	}

	host := ri.Host
	cacheKey := resultcache.DefaultKey(host, qt, ri.QClass, false)
	rm, ok := f.resCache.Get(cacheKey)
	if ok {
		if rm == nil {
			// Return nil explicitly instead of modifying CloneForReq to return
			// nil if the result is nil to avoid a “non-nil nil” value.
			return nil, nil
		}

		return rm.CloneForReq(f.cloner, req), nil
	}

	repHost, ip, ok := f.safeSearchHost(host, qt)
	if !ok {
		optlog.Debug2("filter %s: host %q is not on the list", f.id, host)

		f.resCache.Set(cacheKey, nil)

		return nil, nil
	}

	result, err := f.newRespMsg(ctx, req, fam, ri, ip, repHost)
	if err != nil {
		return nil, fmt.Errorf("filter %s: creating modified result: %w", f.id, err)
	}

	rm = &internal.ResultModified{
		Msg:  result,
		List: f.id,
		Rule: agd.FilterRuleText(host),
	}

	// Copy the result to make sure that modifications to the result message
	// down the pipeline don't interfere with the cached value.
	//
	// See AGDNS-359.
	f.resCache.Set(cacheKey, rm.Clone(f.cloner))

	return rm, nil
}

// ID implements the [internal.RequestFilter] interface for *Filter.
func (f *Filter) ID() (id agd.FilterListID) {
	return f.id
}

// newRespMsg returns a response messages for provided ip and host.
func (f *Filter) newRespMsg(
	ctx context.Context,
	req *dns.Msg,
	fam netutil.AddrFamily,
	ri *agd.RequestInfo,
	ip netip.Addr,
	cname string,
) (msg *dns.Msg, err error) {
	host := cname
	if ip != (netip.Addr{}) {
		// TODO(d.kolyshev): There is no need to resolve this IP if it matches
		// question fam.
		host = ip.String()
	}

	optlog.Debug2("filter %s: found host %q", f.id, host)

	ctx, cancel := context.WithTimeout(ctx, internal.DefaultResolveTimeout)
	defer cancel()

	ips, err := f.resolver.LookupNetIP(ctx, fam, host)
	if err != nil {
		errcoll.Collectf(ctx, f.errColl, "filter %s: resolving: %w", f.id, err)

		return ri.Messages.NewMsgSERVFAIL(req), nil
	}

	if cname != "" {
		return ri.Messages.NewCNAMEWithIPs(req, dns.Fqdn(cname), ips...)
	}

	return ri.Messages.NewIPRespMsg(req, ips...)
}

// safeSearchHost returns the replacement host for the given host and question
// type, if any.  qt should be either [dns.TypeA] or [dns.TypeAAAA].
func (f *Filter) safeSearchHost(
	host string,
	qt dnsmsg.RRType,
) (ssHost string, ip netip.Addr, ok bool) {
	dr := f.flt.DNSResult(netip.Addr{}, "", host, qt, false)
	if dr == nil {
		return "", netip.Addr{}, false
	}

	for _, nr := range dr.DNSRewrites() {
		drw := nr.DNSRewrite
		if drw.RCode != dns.RcodeSuccess {
			continue
		}

		if nc := drw.NewCNAME; nc != "" {
			return nc, netip.Addr{}, true
		}

		// All the rules in safe search rule lists are expected to have either
		// A/AAAA or CNAME type.
		switch drw.RRType {
		case dns.TypeA, dns.TypeAAAA:
			return "", drw.Value.(netip.Addr), true
		default:
			continue
		}
	}

	return "", netip.Addr{}, false
}

// Refresh reloads the rule list data.  If acceptStale is true, and the cache
// file exists, the data is read from there regardless of its staleness.
func (f *Filter) Refresh(ctx context.Context, acceptStale bool) (err error) {
	err = f.flt.Refresh(ctx, acceptStale)
	if err != nil {
		return err
	}

	f.resCache.Clear()

	return nil
}
