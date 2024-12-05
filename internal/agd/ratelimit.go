package agd

import (
	"context"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/c2h5oh/datasize"
	"github.com/miekg/dns"
)

// RatelimitConfig are the rate-limiting settings of a profile.
//
// NOTE: Do not change fields of this structure without incrementing
// [internal/profiledb/internal.FileCacheVersion].
type RatelimitConfig struct {
	// ClientSubnets are the optional subnets for which to apply the custom
	// limit.  If empty, the custom limit is applied to all clients.
	ClientSubnets []netip.Prefix

	// RPS is the rate limit for this profile.
	RPS uint32

	// Enabled defines whether the custom limit should be enforced.
	Enabled bool
}

// Ratelimiter is the interface for profiles' custom ratelimiters.
//
// TODO(a.garipov):  Refactor ratelimit packages.
type Ratelimiter interface {
	// Check reports the result of checking the request against the ratelimiter.
	// req must not be nil.
	Check(ctx context.Context, req *dns.Msg, remoteIP netip.Addr) (res RatelimitResult)

	// Config returns the configuration for this ratelimiter.  conf must never
	// be nil.
	Config() (conf *RatelimitConfig)

	// CountResponses adds the response to the counter.  resp must not be nil.
	CountResponses(ctx context.Context, resp *dns.Msg, remoteIP netip.Addr)
}

// GlobalRatelimiter is a [Ratelimiter] implementation that always returns
// [RatelimitResultUseGlobal] from its Check method.
type GlobalRatelimiter struct{}

// type check
var _ Ratelimiter = GlobalRatelimiter{}

// Check implements the [Ratelimiter] interface for GlobalRatelimiter.  It
// always returns [RatelimitResultUseGlobal].
func (GlobalRatelimiter) Check(_ context.Context, _ *dns.Msg, _ netip.Addr) (res RatelimitResult) {
	return RatelimitResultUseGlobal
}

// Config implements the [Ratelimiter] interface for GlobalRatelimiter.  It
// returns an empty config.
func (GlobalRatelimiter) Config() (_ *RatelimitConfig) { return &RatelimitConfig{} }

// CountResponses implements the [Ratelimiter] interface for GlobalRatelimiter.
func (GlobalRatelimiter) CountResponses(_ context.Context, _ *dns.Msg, _ netip.Addr) {}

// DefaultRatelimiter is the default [Ratelimiter] implementation.
//
// TODO(a.garipov):  Add tests.
type DefaultRatelimiter struct {
	counter       *ratelimit.RequestCounter
	clientSubnets netutil.SliceSubnetSet
	respSzEst     datasize.ByteSize
	rps           uint32
}

// NewDefaultRatelimiter returns a properly initialized *DefaultRatelimiter.
// conf must not be nil.
func NewDefaultRatelimiter(
	conf *RatelimitConfig,
	respSzEst datasize.ByteSize,
) (r *DefaultRatelimiter) {
	return &DefaultRatelimiter{
		counter:       ratelimit.NewRequestCounter(uint(conf.RPS), time.Second),
		clientSubnets: conf.ClientSubnets,
		respSzEst:     respSzEst,
		rps:           conf.RPS,
	}
}

// type check
var _ Ratelimiter = (*DefaultRatelimiter)(nil)

// Check implements the [Ratelimiter] interface for *DefaultRatelimiter.
func (r *DefaultRatelimiter) Check(
	ctx context.Context,
	req *dns.Msg,
	remoteIP netip.Addr,
) (res RatelimitResult) {
	if len(r.clientSubnets) > 0 && !r.clientSubnets.Contains(remoteIP) {
		return RatelimitResultUseGlobal
	}

	if r.counter.Add(time.Now()) {
		return RatelimitResultDrop
	}

	return RatelimitResultPass
}

// Config implements the [Ratelimiter] interface for *DefaultRatelimiter.
func (r *DefaultRatelimiter) Config() (conf *RatelimitConfig) {
	return &RatelimitConfig{
		ClientSubnets: r.clientSubnets,
		RPS:           r.rps,
		Enabled:       true,
	}
}

// CountResponses implements the [Ratelimiter] interface for
// *DefaultRatelimiter.
func (r *DefaultRatelimiter) CountResponses(
	ctx context.Context,
	resp *dns.Msg,
	remoteIP netip.Addr,
) {
	// #nosec G115 -- Assume that resp.Len is always non-negative.
	estRespNum := datasize.ByteSize(resp.Len()) / r.respSzEst
	for range estRespNum {
		_ = r.Check(ctx, resp, remoteIP)
	}
}

// RatelimitResult defines what to do with a request.
type RatelimitResult uint8

// RatelimitResult constants.
const (
	// RatelimitResultPass means that the request should be passed.
	RatelimitResultPass RatelimitResult = iota + 1

	// RatelimitResultDrop means that the request should be dropped.
	RatelimitResultDrop

	// RatelimitResultUseGlobal means that the request should be checked with
	// the global ratelimit.
	RatelimitResultUseGlobal
)
