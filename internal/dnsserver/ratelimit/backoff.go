package ratelimit

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	cache "github.com/patrickmn/go-cache"
)

// Back-Off Rate Limiter

// BackOffConfig is the configuration structure for a back-off rate limiter.
type BackOffConfig struct {
	// Allowlist defines which IP networks are excluded from rate limiting.
	Allowlist Allowlist

	// Period is the time during which the rate limiter counts the number of
	// times a client make more requests than RPS allows to increment the
	// back-off count for the client.
	Period time.Duration

	// Duration is how much a client that has hit the back-off count stays in
	// the back-off state.
	Duration time.Duration

	// Count is how many requests a client makes above the RPS before it is
	// counted as a back-off hit.
	Count int

	// ResponseSizeEstimate is the estimate of the size of one DNS response for
	// the purposes of rate limiting.  Responses over this estimate are counted
	// as several responses.
	ResponseSizeEstimate int

	// RPS is the maximum number of requests per second allowed from a single
	// subnet.  Any requests above this rate are counted as the client's
	// back-off count.  RPS must be greater than zero.
	RPS int

	// IPv4SubnetKeyLen is the length of the subnet prefix used to calculate
	// rate limiter bucket keys for IPv4 addresses.  Must be greater than zero.
	IPv4SubnetKeyLen int

	// IPv6SubnetKeyLen is the length of the subnet prefix used to calculate
	// rate limiter bucket keys for IPv6 addresses.  Must be greater than zero.
	IPv6SubnetKeyLen int

	// RefuseANY tells the rate limiter to refuse DNS requests with the ANY
	// query type (aka *).
	RefuseANY bool
}

// BackOff is the back-off rate limiter which supports allowlists and DNS
// amplification prevention.
//
// TODO(a.garipov): Consider merging this into ratelimit.Middleware.  The
// current implementation might be too abstract.  Middlewares by themselves
// already provide an interface that can be re-implemented by the users.
// Perhaps, another layer of abstraction is unnecessary.
type BackOff struct {
	rpsCounters      *cache.Cache
	hitCounters      *cache.Cache
	allowlist        Allowlist
	count            int
	rps              int
	respSzEst        int
	ipv4SubnetKeyLen int
	ipv6SubnetKeyLen int
	refuseANY        bool
}

// NewBackOff returns a new default rate limiter.
func NewBackOff(c *BackOffConfig) (l *BackOff) {
	// TODO(ameshkov, a.garipov): Consider adding a job or an endpoint for
	// purging the caches to free the map bucket space in the caches.
	return &BackOff{
		// TODO(ameshkov): Consider running the janitor more often.
		rpsCounters:      cache.New(c.Period, c.Period),
		hitCounters:      cache.New(c.Duration, c.Duration),
		allowlist:        c.Allowlist,
		count:            c.Count,
		rps:              c.RPS,
		respSzEst:        c.ResponseSizeEstimate,
		ipv4SubnetKeyLen: c.IPv4SubnetKeyLen,
		ipv6SubnetKeyLen: c.IPv6SubnetKeyLen,
		refuseANY:        c.RefuseANY,
	}
}

// type check
var _ Interface = (*BackOff)(nil)

// IsRateLimited implements the Interface interface for *BackOff.  req must not
// be nil.
func (l *BackOff) IsRateLimited(
	ctx context.Context,
	req *dns.Msg,
	ip netip.Addr,
) (drop, allowlisted bool, err error) {
	err = validateAddr(ip)
	if err != nil {
		return false, false, err
	}

	qType := req.Question[0].Qtype
	if l.refuseANY && qType == dns.TypeANY {
		return true, false, nil
	}

	allowed, err := l.allowlist.IsAllowed(ctx, ip)
	if err != nil {
		return false, false, err
	} else if allowed {
		return false, true, nil
	}

	key := l.subnetKey(ip)
	if l.isBackOff(key) {
		return true, false, nil
	}

	return l.hasHitRateLimit(key), false, nil
}

// validateAddr returns an error if addr is not a valid IPv4 or IPv6 address.
//
// Any error returned will have the underlying type of *netutil.AddrError.
func validateAddr(addr netip.Addr) (err error) {
	if !addr.IsValid() {
		return &netutil.AddrError{
			Kind: netutil.AddrKindIP,
			Addr: addr.String(),
		}
	}

	return nil
}

// CountResponses implements the Interface interface for *BackOff.
func (l *BackOff) CountResponses(ctx context.Context, resp *dns.Msg, ip netip.Addr) {
	respLimit := l.respSzEst
	respSize := resp.Len()
	for i := 0; i < respSize/respLimit; i++ {
		_, _, _ = l.IsRateLimited(ctx, resp, ip)
	}
}

// subnetKey returns the cache key for the subnet of ip.  The key is the string
// representation of ip masked with a specified prefix.  ip is assumed to be
// valid.
func (l *BackOff) subnetKey(ip netip.Addr) (key string) {
	var subnet netip.Prefix
	var err error
	if ip.Is4() {
		subnet, err = ip.Prefix(l.ipv4SubnetKeyLen)
	} else {
		subnet, err = ip.Prefix(l.ipv6SubnetKeyLen)
	}

	if err != nil {
		// Technically shouldn't happen, since ip is required to be valid.
		panic(fmt.Errorf("backoff: getting subnet: %w", err))
	}

	return subnet.String()
}

// incBackOff increments the number of requests above the RPS for a client.
func (l *BackOff) incBackOff(key string) {
	counterVal, ok := l.hitCounters.Get(key)
	if ok {
		counterVal.(*atomic.Int64).Add(1)

		return
	}

	counter := &atomic.Int64{}
	counter.Add(1)
	l.hitCounters.SetDefault(key, counter)
}

// hasHitRateLimit checks value for a subnet.
func (l *BackOff) hasHitRateLimit(subnetIPStr string) (ok bool) {
	var r *rps
	rVal, ok := l.rpsCounters.Get(subnetIPStr)
	if ok {
		r = rVal.(*rps)
	} else {
		r = newRPS(l.rps)
		l.rpsCounters.SetDefault(subnetIPStr, r)
	}

	above := r.add(time.Now())
	if above {
		l.incBackOff(subnetIPStr)
	}

	return above
}

// isBackOff returns true if the specified client has hit the RPS too often.
func (l *BackOff) isBackOff(key string) (ok bool) {
	counterVal, ok := l.hitCounters.Get(key)
	if !ok {
		return false
	}

	return counterVal.(*atomic.Int64).Load() >= int64(l.count)
}
