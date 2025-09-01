// Package cache implements a simple DNS cache that can be used as
// a dnsserver.Middleware.  It also exposes the MetricsListener interface that
// can be used to gather its performance metrics.
package cache

import (
	"cmp"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/bluele/gcache"
	"github.com/miekg/dns"
)

// Middleware is a simple DNS caching middleware with no ECS support.
//
// TODO(a.garipov): Extract cache logic to golibs.
type Middleware struct {
	logger  *slog.Logger
	metrics MetricsListener
	// TODO(d.kolyshev): Use [agdcache.Default].
	cache       gcache.Cache
	cacheMinTTL time.Duration
	overrideTTL bool
}

// MiddlewareConfig is the configuration structure for NewMiddleware.
type MiddlewareConfig struct {
	// Logger is used to log the operation of the middleware.  If Logger is nil,
	// [slog.Default] is used.
	Logger *slog.Logger

	// MetricsListener is the optional listener for the middleware events.  Set
	// it if you want to keep track of what the middleware does and record
	// performance metrics.  If not set, EmptyMetricsListener is used.
	MetricsListener MetricsListener

	// Count is the number of entities to hold in the cache.  It must be
	// positive.
	Count int

	// MinTTL is the minimum supported TTL for cache items.
	MinTTL time.Duration

	// OverrideTTL shows if the TTL overrides logic should be used.
	OverrideTTL bool
}

// NewMiddleware initializes a new LRU caching middleware.  c must not be nil.
func NewMiddleware(c *MiddlewareConfig) (m *Middleware) {
	return &Middleware{
		logger:      cmp.Or(c.Logger, slog.Default()),
		metrics:     cmp.Or[MetricsListener](c.MetricsListener, EmptyMetricsListener{}),
		cache:       gcache.New(c.Count).LRU().Build(),
		cacheMinTTL: c.MinTTL,
		overrideTTL: c.OverrideTTL,
	}
}

// type check
var _ dnsserver.Middleware = (*Middleware)(nil)

// Wrap implements the dnsserver.Middleware interface for *Middleware.
func (m *Middleware) Wrap(handler dnsserver.Handler) (wrapped dnsserver.Handler) {
	f := func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) (err error) {
		defer func() { err = errors.Annotate(err, "cache: %w") }()

		resp, ok := m.get(ctx, req)
		if ok {
			m.metrics.OnCacheHit(ctx, req)

			err = rw.WriteMsg(ctx, req, resp)

			return errors.Annotate(err, "writing cached response: %w")
		}

		m.metrics.OnCacheMiss(ctx, req)

		nrw := dnsserver.NewNonWriterResponseWriter(rw.LocalAddr(), rw.RemoteAddr())
		err = handler.ServeDNS(ctx, nrw, req)
		if err != nil {
			return fmt.Errorf("request processing: %w", err)
		}

		resp = nrw.Msg()
		if resp == nil {
			return nil
		}

		err = m.set(resp)
		m.metrics.OnCacheItemAdded(ctx, resp, m.cache.Len(false))
		if err != nil {
			return fmt.Errorf("adding cache item: %w", err)
		}

		err = rw.WriteMsg(ctx, req, resp)

		return errors.Annotate(err, "writing response: %w")
	}

	return dnsserver.HandlerFunc(f)
}

// get retrieves a DNS message for the specified request from the cache.
func (m *Middleware) get(ctx context.Context, req *dns.Msg) (resp *dns.Msg, found bool) {
	key := toCacheKey(req)
	ciVal, err := m.cache.Get(key)
	if err != nil {
		if !errors.Is(err, gcache.KeyNotFoundError) {
			// Shouldn't happen, since we don't set a serialization function.
			m.logger.ErrorContext(ctx, "retrieving from cache", slogutil.KeyError, err)
		}

		return nil, false
	}

	item, ok := ciVal.(cacheItem)
	if !ok {
		m.logger.ErrorContext(
			ctx,
			"bad type in cache",
			"type", fmt.Sprintf("%T", ciVal),
			"target", req.Question[0].Name,
		)

		return nil, false
	}

	return m.fromCacheItem(item, req), true
}

// set saves msg to the cache if it's cacheable.  If msg cannot be cached, it is
// ignored.
func (m *Middleware) set(msg *dns.Msg) (err error) {
	if m == nil {
		return nil
	}

	ttl := findLowestTTL(msg)
	if ttl == 0 || !isCacheable(msg) {
		return nil
	}

	exp := time.Duration(ttl) * time.Second
	if m.overrideTTL && msg.Rcode != dns.RcodeServerFailure {
		exp = max(exp, m.cacheMinTTL)
		setMinTTL(msg, uint32(exp.Seconds()))
	}

	key := toCacheKey(msg)
	i := m.toCacheItem(msg)

	return m.cache.SetWithExpire(key, i, exp)
}

// toCacheKey returns the cache key for msg.  msg must have one question record.
func toCacheKey(msg *dns.Msg) (k string) {
	q := msg.Question[0]

	// This is a byte array from which we'll make a string key.  It is filled
	// with the following:
	//
	//  - uint8(do)
	//  - uint16(qtype)
	//  - uint16(qclass)
	//  - domain name
	b := make([]byte, 1+2+2+len(q.Name))

	// Put the DO flag.
	if opt := msg.IsEdns0(); opt != nil && opt.Do() {
		b[0] = 1
	}

	// Put qtype, qclass, name.
	binary.BigEndian.PutUint16(b[1:], q.Qtype)
	binary.BigEndian.PutUint16(b[3:], q.Qclass)
	name := strings.ToLower(q.Name)
	copy(b[5:], name)

	return string(b)
}

// isCacheable checks if the DNS message can be cached.  It doesn't consider the
// TTL values of the records.
func isCacheable(msg *dns.Msg) (ok bool) {
	if msg.Truncated || len(msg.Question) != 1 {
		// Don't cache truncated messages and the ones with wrong number of
		// questions.
		return false
	}

	switch msg.Rcode {
	case dns.RcodeSuccess:
		return isCacheableNOERROR(msg)
	case
		dns.RcodeNameError,
		dns.RcodeServerFailure:
		return true
	default:
		// Don't cache if msg is neither a NOERROR, nor NXDOMAIN, nor SERVFAIL.
		return false
	}
}

// isCacheableNOERROR returns true if resp is a cacheable.  resp should be
// a NOERROR response.  resp is considered cacheable if either of the following
// is true:
//
//   - it's a response to a request with the corresponding records present in
//     the answer section; or
//
//   - it's a valid NODATA response to an A or AAAA request with an SOA record
//     in the authority section.
//
// TODO(a.garipov): Consider unifying with findLowestTTL.  It would be nice to
// be able to extract all relevant information about the cacheability of
// a response with one iteration.
func isCacheableNOERROR(resp *dns.Msg) (ok bool) {
	// Iterate through the answer section to find relevant records.  Skip CNAME
	// and SIG records, because a NODATA response may have either no records in
	// the answer section at all or have only these types.  Any other type of
	// record means that this is neither a real response nor a NODATA response.
	//
	// See https://datatracker.ietf.org/doc/html/rfc2308#section-2.2.
	qt := resp.Question[0].Qtype
	for _, rr := range resp.Answer {
		rrType := rr.Header().Rrtype
		switch rrType {
		case qt:
			// This is a normal response to a question.  Cache it.
			return true
		case dns.TypeCNAME, dns.TypeSIG:
			// This could still be a NODATA response.  Go on.
		default:
			// This is a weird, non-NODATA response.  Don't cache it.
			return false
		}
	}

	// Find the SOA record in the authority section if there is one.  If there
	// isn't, this is not a cacheable NODATA response.
	//
	// See https://datatracker.ietf.org/doc/html/rfc2308#section-5.
	for _, rr := range resp.Ns {
		if _, ok = rr.(*dns.SOA); ok {
			return true
		}
	}

	return false
}

// setMinTTL overrides TTL values of all answer records according to the min
// TTL.
func setMinTTL(r *dns.Msg, minTTL uint32) {
	for _, rr := range r.Answer {
		h := rr.Header()

		h.Ttl = max(h.Ttl, minTTL)
	}
}

// findLowestTTL gets the lowest TTL among all DNS message's RRs.
func findLowestTTL(msg *dns.Msg) (ttl uint32) {
	// servFailMaxCacheTTL is the maximum time-to-live value for caching
	// SERVFAIL responses in seconds.  It's consistent with the upper constraint
	// of 5 minutes given by the RFC 2308.
	//
	// See https://datatracker.ietf.org/doc/html/rfc2308#section-7.1.
	const servFailMaxCacheTTL = 30

	// Use the maximum value as a guard value.  If the inner loop is entered,
	// it's going to be rewritten with an actual TTL value that is lower than
	// MaxUint32.  If the inner loop isn't entered, catch that and return zero.
	ttl = math.MaxUint32
	for _, rrs := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range rrs {
			ttl = getTTLIfLower(rr, ttl)
			if ttl == 0 {
				return 0
			}
		}
	}

	switch {
	case msg.Rcode == dns.RcodeServerFailure && ttl > servFailMaxCacheTTL:
		return servFailMaxCacheTTL
	case ttl == math.MaxUint32:
		return 0
	default:
		return ttl
	}
}

// getTTLIfLower is a helper function that checks the TTL of the specified RR
// and returns it if it's lower than the one passed in the arguments.
func getTTLIfLower(r dns.RR, ttl uint32) (res uint32) {
	switch r := r.(type) {
	case *dns.OPT:
		// Don't even consider the OPT RRs TTL.
		return ttl
	case *dns.SOA:
		if r.Minttl > 0 && r.Minttl < ttl {
			// Per RFC 2308, the TTL of a SOA RR is the minimum of SOA.MINIMUM
			// field and the header's value.
			ttl = r.Minttl
		}
	default:
		// Go on.
	}

	if httl := r.Header().Ttl; httl < ttl {
		return httl
	}

	return ttl
}

// cacheItem represents an item that we will store in the cache.
type cacheItem struct {
	// when is the time when msg was cached.
	when time.Time

	// msg is the cached DNS message.
	msg *dns.Msg
}

// toCacheItem creates a cacheItem from a DNS message.
func (m *Middleware) toCacheItem(msg *dns.Msg) (item cacheItem) {
	return cacheItem{
		msg:  msg.Copy(),
		when: time.Now(),
	}
}

// fromCacheItem creates a response from the cached item.
func (m *Middleware) fromCacheItem(item cacheItem, req *dns.Msg) (msg *dns.Msg) {
	msg = &dns.Msg{}
	msg.SetReply(req)

	msg.AuthenticatedData = item.msg.AuthenticatedData
	msg.RecursionAvailable = item.msg.RecursionAvailable
	msg.Compress = item.msg.Compress
	msg.Rcode = item.msg.Rcode

	// Update all the TTL of all depending on when the item was cached.  If it's
	// already expired, update TTL to 0.
	newTTL := findLowestTTL(item.msg)
	if timeLeft := math.Round(float64(newTTL) - time.Since(item.when).Seconds()); timeLeft > 0 {
		newTTL = uint32(timeLeft)
	}

	for _, r := range item.msg.Answer {
		answer := dns.Copy(r)
		answer.Header().Ttl = newTTL
		msg.Answer = append(msg.Answer, answer)
	}

	for _, r := range item.msg.Ns {
		ns := dns.Copy(r)
		ns.Header().Ttl = newTTL
		msg.Ns = append(msg.Ns, ns)
	}

	for _, r := range item.msg.Extra {
		// Don't return OPT records as these are hop-by-hop.
		if r.Header().Rrtype == dns.TypeOPT {
			continue
		}

		extra := dns.Copy(r)
		extra.Header().Ttl = newTTL
		msg.Extra = append(msg.Extra, extra)
	}

	return msg
}
