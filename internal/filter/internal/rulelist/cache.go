package rulelist

import (
	"encoding/binary"
	"hash/maphash"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/golibs/mathutil"
	"github.com/AdguardTeam/urlfilter"
)

// CacheKey is the cache key type for [NewCacheKey].
type CacheKey uint64

// hashSeed is the seed used by all hashes to create hash keys.
var hashSeed = maphash.MakeSeed()

// NewCacheKey produces a cache key based on the arguments using default
// algorithm.
func NewCacheKey(host string, qt dnsmsg.RRType, cl dnsmsg.Class, isAns bool) (k CacheKey) {
	// Use maphash explicitly instead of using a key structure to reduce
	// allocations and optimize interface conversion up the stack.
	h := &maphash.Hash{}
	h.SetSeed(hashSeed)

	_, _ = h.WriteString(host)

	// Save on allocations by reusing a buffer.
	var buf [5]byte
	binary.LittleEndian.PutUint16(buf[:2], qt)
	binary.LittleEndian.PutUint16(buf[2:4], cl)
	buf[4] = mathutil.BoolToNumber[byte](isAns)

	_, _ = h.Write(buf[:])

	return CacheKey(h.Sum64())
}

type (
	// ResultCache is a convenient alias for cache to keep types in check.
	ResultCache = agdcache.Interface[CacheKey, *CacheItem]

	// EmptyResultCache is a convenient alias for empty cache to keep types in
	// check.  See [filter.DNSResult].
	EmptyResultCache = agdcache.Empty[CacheKey, *CacheItem]
)

// NewResultCache returns a new initialized cache with the given element count.
// If useCache is false, it returns a cache implementation that does nothing.
func NewResultCache(count int, useCache bool) (cache ResultCache) {
	if !useCache {
		return EmptyResultCache{}
	}

	return agdcache.NewLRU[CacheKey, *CacheItem](&agdcache.LRUConfig{
		Count: count,
	})
}

// NewManagedResultCache is like [NewResultCache] but it also adds a newly
// created cache to the cache manager by id.
func NewManagedResultCache(
	m agdcache.Manager,
	id string,
	count int,
	useCache bool,
) (cache ResultCache) {
	cache = NewResultCache(count, useCache)
	m.Add(id, cache)

	return cache
}

// CacheItem is an item stored in a [ResultCache].
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
func itemFromCache(cache ResultCache, key CacheKey, host string) (item *CacheItem, ok bool) {
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
