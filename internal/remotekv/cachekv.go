package remotekv

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
)

// Cache is a local cache implementation of the [Interface] interface.
type Cache struct {
	cache agdcache.Interface[string, []byte]
}

// CacheConfig is the configuration for the local cache [Interface]
// implementation.  All fields must not be empty.
type CacheConfig struct {
	// Cache is the underlying cache.
	Cache agdcache.Interface[string, []byte]
}

// NewCache returns a new *Cache.  c must not be nil.
func NewCache(c *CacheConfig) (kv *Cache) {
	return &Cache{
		cache: c.Cache,
	}
}

// type check
var _ Interface = (*Cache)(nil)

// Get implements the [Interface] interface for *Cache.
func (kv *Cache) Get(ctx context.Context, key string) (val []byte, ok bool, err error) {
	val, ok = kv.cache.Get(key)

	return val, ok, nil
}

// Set implements the [Interface] interface for *Cache.
func (kv *Cache) Set(ctx context.Context, key string, val []byte) (err error) {
	kv.cache.Set(key, val)

	return nil
}
