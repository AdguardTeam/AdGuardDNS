// Package rulelist contains the implementation of the standard rule-list
// filter that wraps an urlfilter filtering-engine.
package rulelist

import (
	"context"
	"fmt"

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
	// NOTE:  Do not save the [filterlist.Interface] used to create the engine
	// to close it, because filter exclusively uses [filterlist.StringRuleList],
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
	rulesData []byte,
	id filter.ID,
	svcID filter.BlockedServiceID,
	cache ResultCache,
) (f *baseFilter) {
	f = &baseFilter{
		cache: cache,
		id:    id,
		svcID: svcID,
	}

	lists := []filterlist.Interface{
		filterlist.NewBytes(&filterlist.BytesConfig{
			RulesText:      rulesData,
			IgnoreCosmetic: true,
		}),
	}

	s, err := filterlist.NewRuleStorage(lists)
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

// SetURLFilterResult applies the DNS filtering engine and sets the values in
// res if any have matched.  ok is true if there is a match.  req and res must
// not be nil.
func (f *baseFilter) SetURLFilterResult(
	_ context.Context,
	req *urlfilter.DNSRequest,
	res *urlfilter.DNSResult,
) (ok bool) {
	var cacheKey CacheKey
	var cachedRes *urlfilter.DNSResult

	// Don't waste resources on computing the cache key if the cache is not
	// enabled.
	_, noCache := f.cache.(EmptyResultCache)
	if !noCache {
		// TODO(a.garipov): Add real class here.
		cacheKey = NewCacheKey(req.Hostname, req.DNSType, dns.ClassINET, req.Answer)
		cachedRes, ok = f.cache.Get(cacheKey)
		if ok {
			if cachedRes == nil {
				return false
			}

			shallowCloneInto(res, cachedRes)

			return true
		}
	}

	ok = f.engine.MatchRequestInto(req, res)
	ok = ok || len(res.NetworkRules) > 0

	if noCache {
		return ok
	}

	if ok {
		cachedRes = &urlfilter.DNSResult{}
		shallowCloneInto(cachedRes, res)
	}

	f.cache.Set(cacheKey, cachedRes)

	return ok
}

// shallowCloneInto sets properties in other, as if making a shallow clone.
// other must not be nil and should be empty or reset using [DNSResult.Reset].
//
// TODO(a.garipov):  Add to urlfilter.
func shallowCloneInto(other, res *urlfilter.DNSResult) {
	other.NetworkRule = res.NetworkRule
	other.HostRulesV4 = append(other.HostRulesV4, res.HostRulesV4...)
	other.HostRulesV6 = append(other.HostRulesV6, res.HostRulesV6...)
	other.NetworkRules = append(other.NetworkRules, res.NetworkRules...)
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
