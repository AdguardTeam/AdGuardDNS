// Package agdcache contains cache interfaces, helpers, and implementations.
package agdcache

import (
	"time"
)

// Interface is the cache interface.
type Interface[K, T any] interface {
	// Set sets key and val as cache pair.
	Set(key K, val T)

	// SetWithExpire sets key and val as cache pair with expiration time.
	SetWithExpire(key K, val T, expiration time.Duration)

	// Get gets val from the cache using key.
	Get(key K) (val T, ok bool)

	// Clearer completely clears cache.
	Clearer

	// Len returns the number of items in the cache.
	Len() (n int)
}

// Clearer is a partial cache interface.
type Clearer interface {
	// Clear completely clears cache.
	Clear()
}

// Empty is an [Interface] implementation that does nothing.
type Empty[K, T any] struct{}

// type check
var _ Interface[any, any] = Empty[any, any]{}

// Set implements the [Interface] interface for Empty.
func (c Empty[K, T]) Set(key K, val T) {}

// SetWithExpire implements the [Interface] interface for Empty.
func (c Empty[K, T]) SetWithExpire(key K, val T, expiration time.Duration) {}

// Get implements the [Interface] interface for Empty.
func (c Empty[K, T]) Get(key K) (val T, ok bool) {
	return val, false
}

// type check
var _ Clearer = Empty[any, any]{}

// Clear implements the [Interface] interface for Empty.
func (c Empty[K, T]) Clear() {}

// Len implements the [Interface] interface for Empty.  n may include items that
// have expired, but have not yet been cleaned up.
func (c Empty[K, T]) Len() (n int) {
	return 0
}
