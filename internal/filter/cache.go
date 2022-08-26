package filter

import (
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

// Result Cache

// defaultResultCacheGC is the default interval between two GCs of the result
// cache.
//
// TODO(ameshkov): Consider making configurable.
const defaultResultCacheGC = 1 * time.Minute

// resultCache is a wrapper around gcache.Cache to simplify rare error handling.
type resultCache struct {
	// TODO(a.garipov): This cache should actually be an LRU + expiration cache,
	// but all current implementations are suboptimal.  See AGDNS-398.
	cache *cache.Cache
}

// get returns the cached result, if any.
func (c *resultCache) get(host string, qt dnsmsg.RRType) (r Result, ok bool) {
	v, ok := c.cache.Get(resultCacheKey(host, qt))
	if !ok {
		return nil, false
	}

	return v.(Result), true
}

// set sets the cached result.
func (c *resultCache) set(host string, qt dnsmsg.RRType, r Result) {
	c.cache.SetDefault(resultCacheKey(host, qt), r)
}

// resultCacheKey is the type of the key of a result cache.
func resultCacheKey(host string, qt dnsmsg.RRType) (key string) {
	return dns.Type(qt).String() + " " + host
}
