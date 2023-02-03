package ecscache

import (
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/mathutil"
	"github.com/bluele/gcache"
	"github.com/miekg/dns"
)

// Cache Utilities

// cacheRequest contains data necessary to get a value from the cache.  It is
// used to optimize goroutine stack usage.
type cacheRequest struct {
	host   string
	subnet netip.Prefix
	qType  uint16
	qClass uint16
	reqDO  bool
}

// get retrieves a DNS message for the specified request from the cache, if
// there is one.  If the host was found in the cache for domain names that
// support ECS, hostHasECS is true.  cr, cr.req, and cr.subnet must not be nil.
func (mw *Middleware) get(req *dns.Msg, cr *cacheRequest) (resp *dns.Msg, found, hostHasECS bool) {
	key := mw.toCacheKey(cr, false)
	item, ok := itemFromCache(mw.cache, key, cr)
	if ok {
		return fromCacheItem(item, req, cr.reqDO), true, false
	}

	key = mw.toCacheKey(cr, true)
	item, ok = itemFromCache(mw.ecsCache, key, cr)
	if ok {
		return fromCacheItem(item, req, cr.reqDO), true, true
	}

	return nil, false, false
}

// itemFromCache retrieves a DNS message for the given key.  cr.host is used to
// detect key collisions.  If there is a key collision, it returns nil and
// false.
func itemFromCache(cache gcache.Cache, key uint64, cr *cacheRequest) (item *cacheItem, ok bool) {
	val, err := cache.Get(key)
	if err != nil {
		// Shouldn't happen, since we don't set a serialization function.
		if !errors.Is(err, gcache.KeyNotFoundError) {
			panic(fmt.Errorf("ecs-cache: getting cache item: %w", err))
		}

		return nil, false
	}

	item, ok = val.(*cacheItem)
	if !ok {
		optlog.Error2("ecs-cache: bad type %T of cache item for host %q", val, cr.host)

		return nil, false
	}

	// Check for cache key collisions.
	if item.host != cr.host {
		optlog.Error2("ecs-cache: collision: bad cache item %v for host %q", val, cr.host)

		return nil, false
	}

	return item, true
}

// hashSeed is the seed used by all hashes to create hash keys.
var hashSeed = maphash.MakeSeed()

// toCacheKey returns the appropriate cache key for msg.  msg must have one
// question record.  subnet must not be nil.
func (mw *Middleware) toCacheKey(cr *cacheRequest, hostHasECS bool) (key uint64) {
	// Use maphash explicitly instead of using a key structure to reduce
	// allocations and optimize interface conversion up the stack.
	h := &maphash.Hash{}
	h.SetSeed(hashSeed)

	_, _ = h.WriteString(cr.host)

	// Save on allocations by reusing a buffer.
	var buf [6]byte
	binary.LittleEndian.PutUint16(buf[:2], cr.qType)
	binary.LittleEndian.PutUint16(buf[2:4], cr.qClass)

	buf[4] = mathutil.BoolToNumber[byte](cr.reqDO)

	addr := cr.subnet.Addr()
	buf[5] = mathutil.BoolToNumber[byte](addr.Is6())

	_, _ = h.Write(buf[:])

	if hostHasECS {
		_, _ = h.Write(addr.AsSlice())
		_ = h.WriteByte(byte(cr.subnet.Bits()))
	}

	return h.Sum64()
}

// set saves resp to the cache if it's cacheable.  If msg cannot be cached, it
// is ignored.
func (mw *Middleware) set(resp *dns.Msg, cr *cacheRequest, hostHasECS bool) {
	ttl := findLowestTTL(resp)
	if ttl == 0 || !isCacheable(resp) {
		return
	}

	cache := mw.cache
	if hostHasECS {
		cache = mw.ecsCache
	}

	key := mw.toCacheKey(cr, hostHasECS)
	item := toCacheItem(resp, cr.host)

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

	// host is the cached normalized hostname for later cache key collision
	// checks.
	host string
}

// toCacheItem creates a cacheItem from a DNS message.
func toCacheItem(msg *dns.Msg, host string) (item *cacheItem) {
	return &cacheItem{
		msg:  dnsmsg.Clone(msg),
		when: time.Now(),
		host: host,
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
