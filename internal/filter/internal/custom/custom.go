// Package custom contains the caching storage of filters made from custom
// filtering rules of profiles.
package custom

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/stringutil"
)

// Filters contains custom filters made from custom filtering rules of profiles.
type Filters struct {
	cache   agdcache.Interface[agd.ProfileID, *customFilterCacheItem]
	errColl errcoll.Interface
}

// New returns a new custom filter storage.  It also adds the cache with ID
// [agd.FilterListIDCustom] to the cache manager.
func New(
	conf *agdcache.LRUConfig,
	errColl errcoll.Interface,
	cacheManager agdcache.Manager,
) (f *Filters) {
	cache := agdcache.NewLRU[agd.ProfileID, *customFilterCacheItem](conf)

	cacheManager.Add(string(agd.FilterListIDCustom), cache)

	return &Filters{
		cache:   cache,
		errColl: errColl,
	}
}

// Get returns the custom rule-list filter made from the profile's custom rules
// list, if any.
func (f *Filters) Get(ctx context.Context, p *agd.Profile) (rl *rulelist.Immutable) {
	if len(p.CustomRules) == 0 {
		// Technically, there could be an old filter left in the cache, but it
		// will eventually be evicted, so don't do anything about it.
		return nil
	}

	// Report the custom filters cache lookup to prometheus so that we could
	// keep track of whether the cache size is enough.
	defer func() {
		metrics.IncrementCond(
			rl == nil,
			metrics.FilterCustomCacheLookupsMisses,
			metrics.FilterCustomCacheLookupsHits,
		)
	}()

	rl = f.get(p)
	if rl != nil {
		return rl
	}

	// TODO(a.garipov): Consider making a copy of strings.Join for
	// agd.FilterRuleText.
	textLen := 0
	for _, r := range p.CustomRules {
		textLen += len(r) + len("\n")
	}

	b := &strings.Builder{}
	b.Grow(textLen)

	for _, r := range p.CustomRules {
		stringutil.WriteToBuilder(b, string(r), "\n")
	}

	rl, err := rulelist.NewImmutable(
		b.String(),
		agd.FilterListIDCustom,
		"",
		// Don't use cache for users' custom filters, because resultcache
		// doesn't take $client rules into account.
		//
		// TODO(a.garipov): Consider enabling caching if necessary.
		rulelist.ResultCacheEmpty{},
	)
	if err != nil {
		// In a rare situation where the custom rules are so badly formed that
		// we cannot even create a filtering engine, consider that there is no
		// custom filter, but signal this to the error collector.
		err = fmt.Errorf("compiling custom filter for profile %s: %w", p.ID, err)
		f.errColl.Collect(ctx, err)

		return nil
	}

	log.Info("%s/%s: got %d rules", agd.FilterListIDCustom, p.ID, rl.RulesCount())

	f.set(p, rl)

	return rl
}

// get returns the cached custom rule-list filter, if there is one and the
// profile hasn't changed since the filter was cached.
func (f *Filters) get(p *agd.Profile) (rl *rulelist.Immutable) {
	item, ok := f.cache.Get(p.ID)
	if !ok {
		return nil
	}

	if item.updTime.Before(p.UpdateTime) {
		return nil
	}

	return item.ruleList
}

// set caches the custom rule-list filter.
func (f *Filters) set(p *agd.Profile, rl *rulelist.Immutable) {
	f.cache.Set(p.ID, &customFilterCacheItem{
		updTime:  p.UpdateTime,
		ruleList: rl,
	})
}

// customFilterCacheItem is an item of the custom filter cache.
type customFilterCacheItem struct {
	updTime  time.Time
	ruleList *rulelist.Immutable
}
