package rulelist

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/urlfilter"
)

type (
	// ResultCache is a convenient alias for cache to keep types in check.
	ResultCache = agdcache.Interface[CacheKey, *urlfilter.DNSResult]

	// EmptyResultCache is a convenient alias for empty cache to keep types in
	// check.  See [filter.DNSResult].
	EmptyResultCache = agdcache.Empty[CacheKey, *urlfilter.DNSResult]
)

// NewResultCache returns a new initialized cache with the given element count.
// If useCache is true, count must be positive.  If useCache is false, it
// returns a cache implementation that does nothing.
func NewResultCache(count int, useCache bool) (cache ResultCache) {
	if !useCache {
		return EmptyResultCache{}
	}

	return errors.Must(agdcache.New[CacheKey, *urlfilter.DNSResult](&agdcache.Config{
		Clock: timeutil.SystemClock{},
		Count: count,
	}))
}

// NewManagedResultCache is like [NewResultCache] but it also adds a newly
// created cache to the cache manager by id.  count must be positive.
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

// CacheKey represents a key used in the cache.
type CacheKey struct {
	// host is a non-FQDN version of a cached hostname.
	host string

	// qType is the question type of the DNS request.
	qType uint16

	// qClass is the class of the DNS request.
	qClass uint16

	// isAns is true if the request is an answer.
	isAns bool
}

// NewCacheKey creates a new cache key for the given parameters.
func NewCacheKey(host string, qt dnsmsg.RRType, cl dnsmsg.Class, isAns bool) (key CacheKey) {
	key = CacheKey{
		host:   host,
		qType:  qt,
		qClass: cl,
		isAns:  isAns,
	}

	return key
}
