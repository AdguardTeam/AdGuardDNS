package ecscache

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/bluele/gcache"
	"github.com/miekg/dns"
)

// Cache Utilities

// get retrieves a DNS message for the specified request from the cache, if
// there is one.  If the host was found in the cache for domain names that
// support ECS, hostHasECS is true.  req and subnet must not be nil.
func (m *Middleware) get(
	req *dns.Msg,
	host string,
	subnet netip.Prefix,
	reqDO bool,
) (resp *dns.Msg, found, hostHasECS bool) {
	resp, found = m.getFromCache(req, host, subnet, false, reqDO)
	if found {
		return resp, true, false
	}

	resp, found = m.getFromCache(req, host, subnet, true, reqDO)
	if found {
		return resp, true, true
	}

	return nil, false, false
}

// getFromCache retrieves a DNS message for the specified request data from one
// of the caches depending on the data.  req and subnet must not be nil.
func (m *Middleware) getFromCache(
	req *dns.Msg,
	host string,
	subnet netip.Prefix,
	hostHasECS bool,
	reqDO bool,
) (resp *dns.Msg, found bool) {
	cache := m.cache
	if hostHasECS {
		cache = m.ecsCache
	}

	key := toCacheKey(req, host, subnet, hostHasECS, reqDO)
	ciVal, err := cache.Get(key)
	if err != nil {
		if !errors.Is(err, gcache.KeyNotFoundError) {
			// Shouldn't happen, since we don't set a serialization function.
			panic(fmt.Errorf("ecs-cache: getting cache item: %w", err))
		}

		return nil, false
	}

	item, ok := ciVal.(*cacheItem)
	if !ok {
		log.Error("ecs-cache: bad type %T of cache item for name %q", ciVal, req.Question[0].Name)

		return nil, false
	}

	return fromCacheItem(item, req, reqDO), true
}

// ecsCacheKey is the type of cache keys for responses that indicate ECS
// support.
type ecsCacheKey struct {
	subnet netip.Prefix
	cacheKey
}

// cacheKey is the type of cache keys for responses that indicate no ECS
// support.
type cacheKey struct {
	name   string
	qClass uint16
	qType  dnsmsg.RRType
	reqDO  bool
}

// toCacheKey returns the appropriate cache key for msg.  msg must have one
// question record.  subnet must not be nil.  key is either an ecsCacheKey or a
// cacheKey depending on hostHasECS.
func toCacheKey(
	msg *dns.Msg,
	host string,
	subnet netip.Prefix,
	hostHasECS bool,
	reqDO bool,
) (key any) {
	// NOTE: return structs as opposed to pointers to make sure that the maps
	// inside caches work.

	q := msg.Question[0]
	ck := cacheKey{
		name:   host,
		qClass: q.Qclass,
		qType:  q.Qtype,
		reqDO:  reqDO,
	}

	if !hostHasECS {
		return ck
	}

	return ecsCacheKey{
		subnet:   subnet,
		cacheKey: ck,
	}
}

// set saves resp to the cache if it's cacheable.  If msg cannot be cached, it
// is ignored.
func (m *Middleware) set(
	resp *dns.Msg,
	host string,
	subnet netip.Prefix,
	hostHasECS bool,
	reqDO bool,
) {
	ttl := findLowestTTL(resp)
	if ttl == 0 || !isCacheable(resp) {
		return
	}

	cache := m.cache
	if hostHasECS {
		cache = m.ecsCache
	}

	key := toCacheKey(resp, host, subnet, hostHasECS, reqDO)
	item := toCacheItem(resp)

	err := cache.SetWithExpire(key, item, time.Duration(ttl)*time.Second)
	if err != nil {
		// Shouldn't happen, since we don't set a serialization function.
		panic(fmt.Errorf("ecs-cache: setting cache item: %w", err))
	}
}

// cacheItem represents an item that we will store in the cache.
type cacheItem struct {
	// when is the time when msg was cached.
	when time.Time

	// msg is the cached DNS message.
	msg *dns.Msg
}

// toCacheItem creates a cacheItem from a DNS message.
func toCacheItem(msg *dns.Msg) (item *cacheItem) {
	return &cacheItem{
		msg:  dnsmsg.Clone(msg),
		when: time.Now(),
	}
}

// fromCacheItem creates a response from the cached item.  item and req must not
// be nil.
func fromCacheItem(item *cacheItem, req *dns.Msg, reqDO bool) (msg *dns.Msg) {
	// Update the TTL depending on when the item was cached.  If it's already
	// expired, update TTL to 0.
	newTTL := findLowestTTL(item.msg)
	if timeLeft := time.Duration(newTTL)*time.Second - time.Since(item.when); timeLeft > 0 {
		newTTL = uint32(roundDiv(timeLeft, time.Second))
	} else {
		newTTL = 0
	}

	msg = dnsmsg.Clone(item.msg)
	msg.SetRcode(req, item.msg.Rcode)
	setRespAD(msg, req.AuthenticatedData, reqDO)

	for _, rrs := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range rrs {
			rr.Header().Ttl = newTTL
		}
	}

	return msg
}

// roundDiv divides num by denom, rounding towards nearest integer.  denom must
// not be zero.
//
// TODO(a.garipov): Consider using generics and moving to golibs.
func roundDiv(num, denom time.Duration) (res time.Duration) {
	if (num < 0) == (denom < 0) {
		return (num + denom/2) / denom
	}

	return (num - denom/2) / denom
}
