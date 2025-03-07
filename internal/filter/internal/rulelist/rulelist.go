// Package rulelist contains the implementation of the standard rule-list
// filter that wraps an urlfilter filtering-engine.
package rulelist

import (
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/miekg/dns"
)

// baseFilter is the vase rule-list filter that doesn't refresh or change in any
// other way.
type baseFilter struct {
	// engine is the DNS filtering engine.
	//
	// NOTE:  Do not save the [filterlist.RuleList] used to create the engine to
	// close it, because filter exclusively uses [filterlist.StringRuleList],
	// which doesn't require closing.
	engine *urlfilter.DNSEngine

	// cache contains cached results of filtering.
	//
	// TODO(ameshkov): Add metrics for these caches.
	cache ResultCache

	// id is the filter list ID, if any.
	id filter.ID

	// svcID is the additional identifier for blocked service lists.  If id is
	svcID filter.BlockedServiceID
}

// newBaseFilter returns a new base DNS request and response filter using the
// provided rule text and IDs.
func newBaseFilter(
	text string,
	id filter.ID,
	svcID filter.BlockedServiceID,
	cache ResultCache,
) (f *baseFilter) {
	f = &baseFilter{
		cache: cache,
		id:    id,
		svcID: svcID,
	}

	// TODO(a.garipov): Add filterlist.BytesRuleList.
	strList := &filterlist.StringRuleList{
		RulesText:      text,
		IgnoreCosmetic: true,
	}

	s, err := filterlist.NewRuleStorage([]filterlist.RuleList{strList})
	if err != nil {
		// Should never happen, there is only one filter list, and the only
		// error that is currently returned from [filterlist.NewRuleStorage] is
		// about duplicated IDs.
		panic(fmt.Errorf(
			"rulelist: compiling storage for filter id %q and svc id %q: %w",
			id,
			svcID,
			err,
		))
	}

	f.engine = urlfilter.NewDNSEngine(s)

	return f
}

// DNSResult returns the result of applying the urlfilter DNS filtering engine.
// If the request is not filtered, DNSResult returns nil.
func (f *baseFilter) DNSResult(
	clientIP netip.Addr,
	clientName string,
	host string,
	rrType dnsmsg.RRType,
	isAns bool,
) (res *urlfilter.DNSResult) {
	var ok bool
	var cacheKey CacheKey
	var item *CacheItem

	// Don't waste resources on computing the cache key if the cache is not
	// enabled.
	_, emptyCache := f.cache.(EmptyResultCache)
	if !emptyCache {
		// TODO(a.garipov): Add real class here.
		cacheKey = NewCacheKey(host, rrType, dns.ClassINET, isAns)
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
func (f *baseFilter) ID() (id filter.ID, svcID filter.BlockedServiceID) {
	return f.id, f.svcID
}

// RulesCount returns the number of rules in the filter's engine.
func (f *baseFilter) RulesCount() (n int) {
	return f.engine.RulesCount
}
