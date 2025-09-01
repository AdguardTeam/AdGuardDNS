package agdcache

import (
	"fmt"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/viktordanov/golang-lru/simplelru"
)

// Config is a configuration structure of a cache.
type Config struct {
	// Clock is used to get current time for expiration.  It must not be nil.
	Clock timeutil.Clock

	// Count is the maximum number of elements to keep in the cache.  It must be
	// positive.
	//
	// TODO(a.garipov):  Make uint64.
	Count int
}

// entry is an entry of the cache with expiration.
type entry[T any] struct {
	// val is the value of the entry.
	val T

	// expiration is the expiration unix time in nanoseconds.  Zero means no
	// expiration.  It's an int64 in optimization purposes.
	expiration int64
}

// Default is an implementation of a thread safe, fixed size LRU cache with
// expiration.
type Default[K comparable, T any] struct {
	// cacheMu protects cache.
	cacheMu *sync.RWMutex

	cache *simplelru.LRU[K, entry[T]]
	clock timeutil.Clock
}

// New returns a new initialized *Default cache and error, if any.
func New[K comparable, T any](conf *Config) (c *Default[K, T], err error) {
	lru, err := simplelru.NewLRU[K, entry[T]](conf.Count, nil)
	if err != nil {
		return nil, fmt.Errorf("agdcache: creating lru: %w", err)
	}

	return &Default[K, T]{
		cache:   lru,
		clock:   conf.Clock,
		cacheMu: &sync.RWMutex{},
	}, nil
}

// type check
var _ Interface[any, any] = (*Default[any, any])(nil)

// Set implements the [Interface] interface for *Default.
func (c *Default[K, T]) Set(key K, val T) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	// Not a pointer, but the value is used in optimization purposes.
	e := entry[T]{
		val: val,
	}

	c.cache.Add(key, e)
}

// SetWithExpire implements the [Interface] interface for *Default.
func (c *Default[K, T]) SetWithExpire(key K, val T, duration time.Duration) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	e := entry[T]{
		val:        val,
		expiration: c.clock.Now().Add(duration).UnixNano(),
	}

	c.cache.Add(key, e)
}

// Get implements the [Interface] interface for *Default.  It returns the value
// and whether the key was found.  Removes the key from the cache if it has
// expired.
func (c *Default[K, T]) Get(key K) (val T, ok bool) {
	// TODO(a.garipov):  Optimize, use RLock.
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	e, ok := c.cache.Get(key)
	if !ok {
		return val, false
	}

	if e.expiration > 0 && c.clock.Now().UnixNano() > e.expiration {
		c.cache.Remove(key)

		return val, false
	}

	return e.val, true
}

// type check
var _ Clearer = (*Default[any, any])(nil)

// Clear implements the [Interface] interface for *Default.
func (c *Default[K, T]) Clear() {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	c.cache.Purge()
}

// Len implements the [Interface] interface for *Default.
func (c *Default[K, T]) Len() (n int) {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()

	return c.cache.Len()
}
