package ecscache

import (
	"context"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/miekg/dns"
)

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
func (mw *Middleware) get(
	_ context.Context,
	req *dns.Msg,
	cr *cacheRequest,
) (resp *dns.Msg, isECSDependent bool) {
	key := newCacheKey(cr, false)
	item, ok := mw.cache.Get(key)
	if ok {
		return fromCacheItem(item, mw.cloner, req, cr.reqDO), false
	} else if cr.isECSDeclined {
		return nil, false
	}

	// Try ECS-aware cache.
	key = newCacheKey(cr, true)
	item, ok = mw.ecsCache.Get(key)
	if ok {
		return fromCacheItem(item, mw.cloner, req, cr.reqDO), true
	}

	return nil, false
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
	if mw.overrideTTL && resp.Rcode != dns.RcodeServerFailure {
		exp = max(exp, mw.cacheMinTTL)
		dnsmsg.SetMinTTL(resp, uint32(exp.Seconds()))
	}

	key := newCacheKey(cr, respIsECSDependent)
	cache.SetWithExpire(key, &cacheItem{
		msg:  mw.cloner.Clone(resp),
		when: mw.clock.Now(),
	}, exp)
}

// cacheKey represents a key used in the cache.
type cacheKey struct {
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

// newCacheKey returns the appropriate cache key for msg.  msg must have one
// question record.  cr must not be nil.
func newCacheKey(cr *cacheRequest, respIsECSDependent bool) (key cacheKey) {
	key = cacheKey{
		host:   cr.host,
		qType:  cr.qType,
		qClass: cr.qClass,
		reqDO:  cr.reqDO,
	}

	if respIsECSDependent {
		key.subnet = cr.subnet
	} else {
		key.isECSDeclined = cr.isECSDeclined
	}

	return key
}

// cacheItem represents an item that we will store in the cache.
type cacheItem struct {
	// when is the time when msg was cached.
	when time.Time

	// msg is the cached DNS message.
	msg *dns.Msg
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
		// #nosec G115 -- timeLeft is greater than zero and roundDiv is unlikely
		// to result in something above [math.MaxUint32].
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
