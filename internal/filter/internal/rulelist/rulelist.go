// Package rulelist contains the implementation of the standard rule-list
// filter that wraps an urlfilter filtering-engine.
package rulelist

import (
	"fmt"
	"math/rand"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/resultcache"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/miekg/dns"
)

// newURLFilterID returns a new random ID for the urlfilter DNS engine to use.
func newURLFilterID() (id int) {
	// #nosec G404 -- Do not use cryptographically random ID generation, since
	// these are only used in ../composite/Filter.mustRuleListDataByURLFilterID
	// and are not used in any security-sensitive context.
	//
	// Despite the fact that the type of integer filter list IDs in module
	// urlfilter is int, the module actually assumes that the ID is a
	// non-negative integer, or at least not a largely negative one.  Otherwise,
	// some of its low-level optimizations seem to break.
	return int(rand.Int31())
}

// filter is the basic rule-list filter that doesn't refresh or change in any
// other way.
type filter struct {
	// engine is the DNS filtering engine.
	//
	// NOTE: We do not save the [filterlist.RuleList] used to create the engine
	// to close it, because we exclusively use [filterlist.StringRuleList],
	// which doesn't require closing.
	engine *urlfilter.DNSEngine

	// cache contains cached results of filtering.
	//
	// TODO(ameshkov): Add metrics for these caches.
	cache *resultcache.Cache[*urlfilter.DNSResult]

	// id is the filter list ID, if any.
	id agd.FilterListID

	// svcID is the additional identifier for blocked service lists.  If id is
	svcID agd.BlockedServiceID

	// urlFilterID is the synthetic integer identifier for the urlfilter engine.
	//
	// TODO(a.garipov): Change the type to a string in module urlfilter and
	// remove this crutch.
	urlFilterID int
}

// newFilter returns a new basic DNS request and response filter using the
// provided rule text and ID.
func newFilter(
	text string,
	id agd.FilterListID,
	svcID agd.BlockedServiceID,
	memCacheSize int,
	useMemCache bool,
) (f *filter, err error) {
	f = &filter{
		id:          id,
		svcID:       svcID,
		urlFilterID: newURLFilterID(),
	}

	if useMemCache {
		f.cache = resultcache.New[*urlfilter.DNSResult](memCacheSize)
	}

	// TODO(a.garipov): Add filterlist.BytesRuleList.
	strList := &filterlist.StringRuleList{
		ID:             f.urlFilterID,
		RulesText:      text,
		IgnoreCosmetic: true,
	}

	s, err := filterlist.NewRuleStorage([]filterlist.RuleList{strList})
	if err != nil {
		return nil, fmt.Errorf("creating rule storage: %w", err)
	}

	f.engine = urlfilter.NewDNSEngine(s)

	return f, nil
}

// DNSResult returns the result of applying the urlfilter DNS filtering engine.
// If the request is not filtered, DNSResult returns nil.
func (f *filter) DNSResult(
	clientIP netip.Addr,
	clientName string,
	host string,
	rrType dnsmsg.RRType,
	isAns bool,
) (res *urlfilter.DNSResult) {
	var ok bool
	var cacheKey resultcache.Key

	// Don't waste resources on computing the cache key if the cache is not
	// enabled.
	useCache := f.cache != nil
	if useCache {
		// TODO(a.garipov): Add real class here.
		cacheKey = resultcache.DefaultKey(host, rrType, dns.ClassINET, isAns)
		res, ok = f.cache.Get(cacheKey)
		if ok {
			return res
		}
	}

	dnsReq := &urlfilter.DNSRequest{
		Hostname: host,
		// TODO(a.garipov): Make this a net.IP in module urlfilter.
		ClientIP:   clientIP.String(),
		ClientName: clientName,
		DNSType:    rrType,
		Answer:     isAns,
	}

	res, ok = f.engine.MatchRequest(dnsReq)
	if !ok && len(res.NetworkRules) == 0 {
		res = nil
	}

	if useCache {
		f.cache.Set(cacheKey, res)
	}

	return res
}

// ID returns the filter list ID of this rule list filter, as well as the ID of
// the blocked service, if any.
func (f *filter) ID() (id agd.FilterListID, svcID agd.BlockedServiceID) {
	return f.id, f.svcID
}

// RulesCount returns the number of rules in the filter's engine.
func (f *filter) RulesCount() (n int) {
	return f.engine.RulesCount
}

// URLFilterID returns the synthetic ID used for the urlfilter module.
func (f *filter) URLFilterID() (n int) {
	return f.urlFilterID
}
