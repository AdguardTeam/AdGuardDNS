package filter

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/stringutil"
	"github.com/bluele/gcache"
)

// Custom Filters For Profiles

// customFilters contains custom filters made from custom filtering rules of
// profiles.
type customFilters struct {
	cache   gcache.Cache
	errColl agd.ErrorCollector
}

// appendRuleLists appends the custom rule list filter made from the profile's
// custom rules list, if any, to rls.
func (f *customFilters) appendRuleLists(
	ctx context.Context,
	rls []*ruleListFilter,
	p *agd.Profile,
) (res []*ruleListFilter) {
	if len(p.CustomRules) == 0 {
		// Technically, there could be an old filter left in the cache, but it
		// will eventually be evicted, so don't do anything about it.
		return rls
	}

	optlog.Debug2("%s: compiling custom filter for profile %s", strgLogPrefix, p.ID)
	defer optlog.Debug2("%s: finished compiling custom filter for profile %s", strgLogPrefix, p.ID)

	// Report the custom filters cache lookup to prometheus so that we could
	// keep track of whether the cache size is enough.
	defer func() {
		if rls == nil {
			metrics.FilterCustomCacheLookupsMisses.Inc()
		} else {
			metrics.FilterCustomCacheLookupsHits.Inc()
		}
	}()

	rl := f.get(p)
	if rl != nil {
		return append(rls, rl)
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

	// Don't use cache for users' custom filters.
	rl, err := newRuleListFltFromStr(b.String(), agd.FilterListIDCustom, string(p.ID), 0, false)
	if err != nil {
		// In a rare situation where the custom rules are so badly formed that
		// we cannot even create a filtering engine, consider that there is no
		// custom filter, but signal this to the error collector.
		err = fmt.Errorf("compiling custom filter for profile %s: %w", p.ID, err)
		f.errColl.Collect(ctx, err)

		return nil
	}

	f.set(p, rl)

	return append(rls, rl)
}

// get returns the cached custom rule list filter, if there is one and the
// profile hasn't changed since the filter was cached.
func (f *customFilters) get(p *agd.Profile) (rl *ruleListFilter) {
	itemVal, err := f.cache.Get(p.ID)
	if errors.Is(err, gcache.KeyNotFoundError) {
		return nil
	} else if err != nil {
		// Shouldn't happen, since we don't set a serialization function.
		panic(err)
	}

	item := itemVal.(*customFilterCacheItem)
	if item.updTime.Before(p.UpdateTime) {
		return nil
	}

	return item.ruleList
}

// set caches the custom rule list filter.
func (f *customFilters) set(p *agd.Profile, rl *ruleListFilter) {
	item := &customFilterCacheItem{
		updTime:  p.UpdateTime,
		ruleList: rl,
	}

	err := f.cache.Set(p.ID, item)
	if err != nil {
		// Shouldn't happen, since we don't set a serialization function.
		panic(err)
	}
}

// customFilterCacheItem is an item of the custom filter cache.
type customFilterCacheItem struct {
	updTime  time.Time
	ruleList *ruleListFilter
}
