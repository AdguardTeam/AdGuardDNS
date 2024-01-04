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
	// host is a non-FQDN version of a cached hostname.
	host string

	// subnet is the network of the country the DNS request came from determined
	// with GeoIP.
	subnet netip.Prefix

	// qType is the question type of the DNS request.
	qType uint16

	// qClass is the class of the DNS request.
	qClass uint16

	// reqDO is the state of DNSSEC OK bit from the DNS request.
	reqDO bool

	// isECSDeclined reflects if the client explicitly restricts using its
	// information in EDNS client subnet option as per RFC 7871.
	//
	// See https://datatracker.ietf.org/doc/html/rfc7871#section-7.1.2.
	isECSDeclined bool
}

// get retrieves a DNS message for the specified request from the cache, if
// there is one.  If the host was found in the cache for domain names that
// support ECS, isECSDependent is true.  cr, cr.req, and cr.subnet must not be
// nil.
func (mw *Middleware) get(req *dns.Msg, cr *cacheRequest) (resp *dns.Msg, isECSDependent bool) {
	key := mw.toCacheKey(cr, false)
	item, ok := itemFromCache(mw.cache, key, cr)
	if ok {
		return fromCacheItem(item, mw.cloner, req, cr.reqDO), false
	} else if cr.isECSDeclined {
		return nil, false
	}

	// Try ECS-aware cache.
	key = mw.toCacheKey(cr, true)
	item, ok = itemFromCache(mw.ecsCache, key, cr)
	if ok {
		return fromCacheItem(item, mw.cloner, req, cr.reqDO), true
	}

	return nil, false
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
func (mw *Middleware) toCacheKey(cr *cacheRequest, respIsECSDependent bool) (key uint64) {
	// Use maphash explicitly instead of using a key structure to reduce
	// allocations and optimize interface conversion up the stack.
	//
	// TODO(a.garipov, e.burkov):  Consider just using struct as a key.
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

	if respIsECSDependent {
		_, _ = h.Write(addr.AsSlice())
		_ = h.WriteByte(byte(cr.subnet.Bits()))
	} else {
		_ = h.WriteByte(mathutil.BoolToNumber[byte](cr.isECSDeclined))
	}

	return h.Sum64()
}

// set saves resp to the cache if it's cacheable.  If msg cannot be cached, it
// is ignored.
func (mw *Middleware) set(resp *dns.Msg, cr *cacheRequest, respIsECSDependent bool) {
	ttl := dnsmsg.FindLowestTTL(resp)
	if ttl == 0 || !isCacheable(resp) {
		return
	}

	cache := mw.cache
	if respIsECSDependent {
		cache = mw.ecsCache
	}

	exp := time.Duration(ttl) * time.Second
	if mw.useTTLOverride && resp.Rcode != dns.RcodeServerFailure {
		exp = max(exp, mw.cacheMinTTL)
		dnsmsg.SetMinTTL(resp, uint32(exp.Seconds()))
	}

	key := mw.toCacheKey(cr, respIsECSDependent)

	cachedResp := mw.cloner.Clone(resp)

	item := toCacheItem(cachedResp, cr.host)
	err := cache.SetWithExpire(key, item, exp)
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

// toCacheItem creates a *cacheItem from a DNS message.
func toCacheItem(resp *dns.Msg, host string) (item *cacheItem) {
	return &cacheItem{
		msg:  resp,
		when: time.Now(),
		host: host,
	}
}

// fromCacheItem creates a response from the cached item.  item, cloner, and req
// must not be nil.
func fromCacheItem(
	item *cacheItem,
	cloner *dnsmsg.Cloner,
	req *dns.Msg,
	reqDO bool,
) (resp *dns.Msg) {
	// Update the TTL depending on when the item was cached.  If it's already
	// expired, update TTL to 0.
	newTTL := dnsmsg.FindLowestTTL(item.msg)
	if timeLeft := time.Duration(newTTL)*time.Second - time.Since(item.when); timeLeft > 0 {
		newTTL = uint32(roundDiv(timeLeft, time.Second))
	} else {
		newTTL = 0
	}

	resp = cloner.Clone(item.msg)

	resp.SetRcode(req, item.msg.Rcode)
	setRespAD(resp, req.AuthenticatedData, reqDO)

	for _, rrs := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, rr := range rrs {
			rr.Header().Ttl = newTTL
		}
	}

	return resp
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
