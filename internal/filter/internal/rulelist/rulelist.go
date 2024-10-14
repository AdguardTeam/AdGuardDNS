// Package rulelist contains the implementation of the standard rule-list
// filter that wraps an urlfilter filtering-engine.
package rulelist

import (
	"fmt"
	"math/rand"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
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

type (
	// ResultCache is a convenient alias for cache to keep types in check.
	ResultCache = agdcache.Interface[internal.CacheKey, *CacheItem]

	// ResultCacheEmpty is a convenient alias for empty cache to keep types in
	// check.  See [filter.DNSResult].
	ResultCacheEmpty = agdcache.Empty[internal.CacheKey, *CacheItem]
)

// NewResultCache returns a new initialized cache with the given size.  If
// useCache is false, it returns a cache implementation that does nothing.
func NewResultCache(size int, useCache bool) (cache ResultCache) {
	if !useCache {
		return ResultCacheEmpty{}
	}

	return agdcache.NewLRU[internal.CacheKey, *CacheItem](&agdcache.LRUConfig{
		Size: size,
	})
}

// NewManagedResultCache is like [NewResultCache] but it also adds a newly
// created cache to the cache manager by id.
func NewManagedResultCache(
	m agdcache.Manager,
	id string,
	size int,
	useCache bool,
) (cache ResultCache) {
	cache = NewResultCache(size, useCache)
	m.Add(id, cache)

	return cache
}

// CacheItem represents an item that we will store in the cache.
type CacheItem struct {
	// res is the DNS filtering result.
	res *urlfilter.DNSResult

	// host is the cached normalized hostname for later cache key collision
	// checks.
	host string
}

// itemFromCache retrieves a cache item for the given key.  host is used to
// detect key collisions.  If there is a key collision, it returns nil and
// false.
func itemFromCache(
	cache ResultCache,
	key internal.CacheKey,
	host string,
) (item *CacheItem, ok bool) {
	item, ok = cache.Get(key)
	if !ok {
		return nil, false
	}

	if item.host != host {
		// Cache collision.
		return nil, false
	}

	return item, true
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
	cache ResultCache

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
	cache agdcache.Interface[internal.CacheKey, *CacheItem],
) (f *filter, err error) {
	f = &filter{
		cache:       cache,
		id:          id,
		svcID:       svcID,
		urlFilterID: newURLFilterID(),
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
	var cacheKey internal.CacheKey
	var item *CacheItem

	// Don't waste resources on computing the cache key if the cache is not
	// enabled.
	_, emptyCache := f.cache.(ResultCacheEmpty)
	if !emptyCache {
		// TODO(a.garipov): Add real class here.
		cacheKey = internal.NewCacheKey(host, rrType, dns.ClassINET, isAns)
		item, ok = itemFromCache(f.cache, cacheKey, host)
		if ok {
			return item.res
		}
	}

	dnsReq := &urlfilter.DNSRequest{
		Hostname:   host,
		ClientIP:   clientIP,
		ClientName: clientName,
		DNSType:    rrType,
		Answer:     isAns,
	}

	res, ok = f.engine.MatchRequest(dnsReq)
	if !ok && len(res.NetworkRules) == 0 {
		res = nil
	}

	f.cache.Set(cacheKey, &CacheItem{
		res:  res,
		host: host,
	})

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
