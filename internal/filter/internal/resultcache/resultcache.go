// Package resultcache contains a cache for filtering results.
package resultcache

import (
	"encoding/binary"
	"fmt"
	"hash/maphash"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/mathutil"
	"github.com/bluele/gcache"
)

// Cache is a wrapper around [gcache.Cache] to simplify rare error handling.
type Cache[T any] struct {
	// TODO(a.garipov): This cache should actually be an LRU + expiration cache,
	// but all current implementations are suboptimal.  See AGDNS-398.
	cache gcache.Cache
}

// New returns a new LRU result cache with the given size.
func New[T any](size int) (c *Cache[T]) {
	return &Cache[T]{
		cache: gcache.New(size).LRU().Build(),
	}
}

// Clear clears the cache.  If c is nil, nothing is done.
func (c *Cache[T]) Clear() {
	if c != nil {
		c.cache.Purge()
	}
}

// Key is the type of result cache keys.
type Key uint64

// Get returns the cached result, if any.  If c is nil, Get returns a zero T and
// false.
func (c *Cache[T]) Get(k Key) (r T, ok bool) {
	if c == nil {
		return r, false
	}

	v, err := c.cache.Get(k)
	if err != nil {
		if !errors.Is(err, gcache.KeyNotFoundError) {
			// Shouldn't happen, since we don't set a serialization function.
			panic(fmt.Errorf("resultcache: getting cache item: %w", err))
		}

		return r, false
	}

	return v.(T), true
}

// ItemCount returns the number of items in the cache.  This may include items
// that have expired, but have not yet been cleaned up.  If c is nil, ItemCount
// returns 0.
func (c *Cache[T]) ItemCount() (n int) {
	if c == nil {
		return 0
	}

	return c.cache.Len(false)
}

// Set sets the cached result.  If c is nil, nothing is done.
func (c *Cache[T]) Set(k Key, r T) {
	if c != nil {
		err := c.cache.Set(k, r)
		if err != nil {
			// Shouldn't happen, since we don't set a serialization function.
			panic(fmt.Errorf("resultcache: setting cache item: %w", err))
		}
	}
}

// hashSeed is the seed used by all hashes to create hash keys.
var hashSeed = maphash.MakeSeed()

// DefaultKey produces a cache key based on host, qt, and isAns using the
// default algorithm.
func DefaultKey(host string, qt dnsmsg.RRType, isAns bool) (k Key) {
	// Use maphash explicitly instead of using a key structure to reduce
	// allocations and optimize interface conversion up the stack.
	h := &maphash.Hash{}
	h.SetSeed(hashSeed)

	_, _ = h.WriteString(host)

	// Save on allocations by reusing a buffer.
	var buf [3]byte
	binary.LittleEndian.PutUint16(buf[:2], qt)
	buf[2] = mathutil.BoolToNumber[byte](isAns)

	_, _ = h.Write(buf[:])

	return Key(h.Sum64())
}
