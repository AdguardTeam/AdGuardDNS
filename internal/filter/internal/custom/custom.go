// Package custom contains the caching storage of filters made from custom
// filtering rules of clients.
package custom

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/stringutil"
)

// Filters contains custom filters made from custom filtering rules of clients.
type Filters struct {
	logger  *slog.Logger
	cache   agdcache.Interface[string, *cacheItem]
	errColl errcoll.Interface
}

// cacheItem is an item of the custom filter cache.
type cacheItem struct {
	updTime  time.Time
	ruleList *rulelist.Immutable
}

// CacheID is a cache identifier for clients' custom filters.
const CacheID = "filters/" + string(internal.IDCustom)

// Config is the configuration structure for the custom-filter storage.  All
// fields must not be nil.
type Config struct {
	// Logger is used to log the operation of the storage.
	Logger *slog.Logger

	// ErrColl is used to collect errors arising during engine compilation.
	ErrColl errcoll.Interface

	// CacheConf is used as the configuration for the cache.
	CacheConf *agdcache.LRUConfig

	// CacheManager is used to create the cache for the storage.
	CacheManager agdcache.Manager
}

// New returns a new custom filter storage.  It also adds the cache with ID
// [CacheID] to the cache manager.  c must not be nil.
func New(c *Config) (f *Filters) {
	cache := agdcache.NewLRU[string, *cacheItem](c.CacheConf)
	c.CacheManager.Add(CacheID, cache)

	return &Filters{
		logger:  c.Logger,
		cache:   cache,
		errColl: c.ErrColl,
	}
}

// ClientConfig is the configuration for identification or construction of a
// custom filter for a client.
type ClientConfig = internal.ConfigCustom

// Get returns the custom rule-list filter made from the client configuration.
// c must not be nil.
func (f *Filters) Get(ctx context.Context, c *ClientConfig) (rl *rulelist.Immutable) {
	if !c.Enabled || len(c.Rules) == 0 {
		// Technically, there could be an old filter left in the cache, but it
		// will eventually be evicted, so don't do anything about it.
		return nil
	}

	// Report the custom filters cache lookup to prometheus so that we could
	// keep track of whether the cache size is enough.
	defer func() {
		// TODO(a.garipov):  Add a Metrics interface.
		metrics.IncrementCond(
			rl == nil,
			metrics.FilterCustomCacheLookupsMisses,
			metrics.FilterCustomCacheLookupsHits,
		)
	}()

	rl = f.get(c)
	if rl != nil {
		return rl
	}

	// TODO(a.garipov): Consider making a copy of [strings.Join] for
	// [internal.RuleText].
	textLen := 0
	for _, r := range c.Rules {
		textLen += len(r) + len("\n")
	}

	b := &strings.Builder{}
	b.Grow(textLen)

	for _, r := range c.Rules {
		stringutil.WriteToBuilder(b, string(r), "\n")
	}

	rl, err := rulelist.NewImmutable(
		b.String(),
		internal.IDCustom,
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
		err = fmt.Errorf("compiling custom filter for client with id %s: %w", c.ID, err)
		f.errColl.Collect(ctx, err)

		return nil
	}

	f.logger.DebugContext(
		ctx,
		"got rules for client",
		"client_id", c.ID,
		"num_rules", rl.RulesCount(),
	)

	f.set(c, rl)

	return rl
}

// get returns the cached custom rule-list filter, if there is one and the
// client configuration hasn't changed since the filter was cached.
func (f *Filters) get(c *ClientConfig) (rl *rulelist.Immutable) {
	item, ok := f.cache.Get(c.ID)
	if !ok {
		return nil
	}

	if item.updTime.Before(c.UpdateTime) {
		return nil
	}

	return item.ruleList
}

// set caches the custom rule-list filter.
func (f *Filters) set(c *ClientConfig, rl *rulelist.Immutable) {
	f.cache.Set(c.ID, &cacheItem{
		updTime:  c.UpdateTime,
		ruleList: rl,
	})
}
