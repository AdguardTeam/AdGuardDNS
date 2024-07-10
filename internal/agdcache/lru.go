package agdcache

import (
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/bluele/gcache"
)

// LRUConfig is a configuration structure of a cache.
type LRUConfig struct {
	Size int
}

// LRU is an [Interface] implementation.
type LRU[K, T any] struct {
	cache gcache.Cache
}

// NewLRU returns a new initialized LRU cache.
func NewLRU[K, T any](conf *LRUConfig) (c *LRU[K, T]) {
	return &LRU[K, T]{
		cache: gcache.New(conf.Size).LRU().Build(),
	}
}

// type check
var _ Interface[any, any] = (*LRU[any, any])(nil)

// Set implements the [Interface] interface for *LRU.
func (c *LRU[K, T]) Set(key K, val T) {
	err := c.cache.Set(key, val)
	if err != nil {
		// Shouldn't happen, since we don't set a serialization function.
		panic(fmt.Errorf("agdcache: setting cache item: %w", err))
	}
}

// SetWithExpire implements the [Interface] interface for *LRU.
func (c *LRU[K, T]) SetWithExpire(key K, val T, expiration time.Duration) {
	err := c.cache.SetWithExpire(key, val, expiration)
	if err != nil {
		// Shouldn't happen, since we don't set a serialization function.
		panic(fmt.Errorf("agdcache: setting cache item with expiration: %w", err))
	}
}

// Get implements the [Interface] interface for *LRU.
func (c *LRU[K, T]) Get(key K) (val T, ok bool) {
	v, err := c.cache.Get(key)
	if err != nil {
		if !errors.Is(err, gcache.KeyNotFoundError) {
			// Shouldn't happen, since we don't set a serialization function.
			panic(fmt.Errorf("agdcache: getting cache item: %w", err))
		}

		return val, false
	}

	// T may be an interface type, so check v against nil explicitly to prevent
	// v.(T) below from panicking.
	if v == nil {
		return val, true
	}

	return v.(T), true
}

// type check
var _ Clearer = (*LRU[any, any])(nil)

// Clear implements the [Interface] interface for *LRU.
func (c *LRU[K, T]) Clear() {
	c.cache.Purge()
}

// Len implements the [Interface] interface for *LRU.  n may include items
// that have expired, but have not yet been cleaned up.
func (c *LRU[K, T]) Len() (n int) {
	const checkExpired = false

	return c.cache.Len(checkExpired)
}
