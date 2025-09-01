// Package ecscache implements a EDNS Client Subnet (ECS) aware DNS cache that
// can be used as a [dnsserver.Middleware].
package ecscache

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/optslog"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
)

// MiddlewareConfig is the configuration structure for [NewMiddleware].
type MiddlewareConfig struct {
	// Metrics is used for the collection of the ECS cache middleware
	// statistics.  It must not be nil.
	Metrics Metrics

	// Clock is used for getting current time.  It must not be nil.
	Clock timeutil.Clock

	// Cloner is used to clone messages taken from cache.  It must not be nil.
	Cloner *dnsmsg.Cloner

	// Logger is used to log the operation of the middleware.  It must not be
	// nil.
	Logger *slog.Logger

	// CacheManager is the global cache manager.  It must not be nil.
	CacheManager agdcache.Manager

	// GeoIP is the GeoIP database used to get subnets for countries.  It must
	// not be nil.
	GeoIP geoip.Interface

	// MinTTL is the minimum supported TTL for cache items.
	MinTTL time.Duration

	// NoECSCount is the number of entities to hold in the cache for hosts that
	// don't support ECS, in entries.  It must be greater than zero.
	NoECSCount int

	// ECSCount is the number of entities to hold in the cache for hosts that
	// support ECS, in entries.  It must be greater than zero.
	ECSCount int

	// OverrideTTL shows if the TTL overrides logic should be used.
	OverrideTTL bool
}

// Middleware is a dnsserver.Middleware with ECS-aware caching.
type Middleware struct {
	// clock is used to get current time for cache expiration.
	clock timeutil.Clock

	// metrics is used for the collection of the ECS cache statistics.
	metrics Metrics

	// cloner is the memory-efficient cloner of DNS messages.
	cloner *dnsmsg.Cloner

	// cacheReqPool is a pool of cache requests.
	cacheReqPool *syncutil.Pool[cacheRequest]

	// logger is used to log the operation of the middleware.
	logger *slog.Logger

	// cache is the LRU cache for results indicating no support for ECS.
	cache agdcache.Interface[cacheKey, *cacheItem]

	// ecsCache is the LRU cache for results indicating ECS support.
	ecsCache agdcache.Interface[cacheKey, *cacheItem]

	// geoIP is used to get subnets for countries.
	geoIP geoip.Interface

	// cacheMinTTL is the minimum supported TTL for cache items.
	cacheMinTTL time.Duration

	// overrideTTL shows if the TTL overrides logic should be used.
	overrideTTL bool
}

// Constants that define cache identifiers for the cache manager.
const (
	cachePrefix    = "dns/"
	cacheIDWithECS = cachePrefix + "ecscache_with_ecs"
	cacheIDNoECS   = cachePrefix + "ecscache_no_ecs"
)

// NewMiddleware initializes a new ECS-aware LRU caching middleware.  It also
// adds the caches with IDs [CacheIDNoECS] and [CacheIDWithECS] to the cache
// manager.  c must not be nil.
func NewMiddleware(c *MiddlewareConfig) (m *Middleware) {
	cache := errors.Must(agdcache.New[cacheKey, *cacheItem](&agdcache.Config{
		Clock: c.Clock,
		Count: c.NoECSCount,
	}))
	ecsCache := errors.Must(agdcache.New[cacheKey, *cacheItem](&agdcache.Config{
		Clock: c.Clock,
		Count: c.ECSCount,
	}))

	c.CacheManager.Add(cacheIDNoECS, cache)
	c.CacheManager.Add(cacheIDWithECS, ecsCache)

	return &Middleware{
		clock:   c.Clock,
		metrics: c.Metrics,
		cloner:  c.Cloner,
		logger:  c.Logger,
		cacheReqPool: syncutil.NewPool(func() (req *cacheRequest) {
			return &cacheRequest{}
		}),
		cache:       cache,
		ecsCache:    ecsCache,
		geoIP:       c.GeoIP,
		cacheMinTTL: c.MinTTL,
		overrideTTL: c.OverrideTTL,
	}
}

// type check
var _ dnsserver.Middleware = (*Middleware)(nil)

// Wrap implements the dnsserver.Middleware interface for *Middleware.
func (mw *Middleware) Wrap(h dnsserver.Handler) (wrapped dnsserver.Handler) {
	return &mwHandler{
		mw:   mw,
		next: h,
	}
}

// writeCachedResponse writes resp to rw replacing the ECS data and incrementing
// cache hit metrics if necessary.
func writeCachedResponse(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	resp *dns.Msg,
	ecs *dnsmsg.ECS,
	ecsFam netutil.AddrFamily,
) (err error) {
	// If the client query did include the ECS option, the server MUST include
	// one in its response.
	//
	// See https://datatracker.ietf.org/doc/html/rfc7871#section-7.2.2.
	if ecs != nil {
		err = setECS(resp, ecs, ecsFam, true)
		if err != nil {
			return fmt.Errorf("setting ecs for cached resp: %w", err)
		}
	}

	// resp doesn't need additional filtering, since all hop-to-hop data has
	// been filtered when setting the cache, and the AD bit was set when resp
	// was being retrieved from the cache.
	err = rw.WriteMsg(ctx, req, resp)
	if err != nil {
		return fmt.Errorf("writing cached resp: %w", err)
	}

	return nil
}

// ecsFamFromReq returns the address family to use for the outgoing request from
// the request information using either the contents of the EDNS Client Subnet
// option or the real remote IP address.
func ecsFamFromReq(ri *agd.RequestInfo) (ecsFam netutil.AddrFamily) {
	// Assume that families other than IPv4 and IPv6 have been filtered out
	// by dnsmsg.ECSFromMsg.

	// Set the address family parameter to the one of the client's address
	// as per RFC 7871.
	//
	// See https://datatracker.ietf.org/doc/html/rfc7871#section-7.1.1.
	addr := ri.RemoteIP
	if ecs := ri.ECS; ecs != nil {
		addr = ecs.Subnet.Addr()
	}

	if addr.Is4() {
		return netutil.AddrFamilyIPv4
	}

	return netutil.AddrFamilyIPv6
}

// locFromReq returns the location from the request information using either the
// contents of the EDNS Client Subnet option or the real remote address.
func locFromReq(ri *agd.RequestInfo) (l *geoip.Location) {
	var ctry geoip.Country
	var subdiv string
	var asn geoip.ASN
	if ecs := ri.ECS; ecs != nil && ecs.Location != nil {
		ctry = ecs.Location.Country
		subdiv = ecs.Location.TopSubdivision
		asn = ecs.Location.ASN
	}

	if ctry == geoip.CountryNone && ri.Location != nil {
		ctry = ri.Location.Country
		asn = ri.Location.ASN
	}

	return &geoip.Location{
		Country:        ctry,
		TopSubdivision: subdiv,
		ASN:            asn,
	}
}

// writeUpstreamResponse processes, caches, and writes the response to rw as
// well as updates cache metrics.
func (mw *Middleware) writeUpstreamResponse(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	resp *dns.Msg,
	ri *agd.RequestInfo,
	cr *cacheRequest,
	ecsFam netutil.AddrFamily,
) (err error) {
	subnet, scope, err := dnsmsg.ECSFromMsg(resp)
	if err != nil {
		return fmt.Errorf("getting ecs from resp: %w", err)
	}

	optslog.Trace2(ctx, mw.logger, "upstream data", "subnet", subnet, "scope", scope)

	reqDO := cr.reqDO
	rmHopToHopData(resp, ri.QType, reqDO)

	respIsECS := respIsECSDependent(scope, req.Question[0].Name)

	var cache agdcache.Interface[cacheKey, *cacheItem]
	if respIsECS {
		cache = mw.ecsCache
	} else {
		cache = mw.cache
		cr.subnet = netutil.ZeroPrefix(ecsFam)
	}

	mw.metrics.SetElementsCount(ctx, respIsECS, cache.Len())
	mw.metrics.IncrementLookups(ctx, respIsECS, false)

	mw.set(resp, cr, respIsECS)

	// Set the AD bit and ECS information here, where it is safe to do so, since
	// a clone of the otherwise filtered response has already been set to cache.
	setRespAD(resp, req.AuthenticatedData, reqDO)

	// If the client query did include the ECS option, the server MUST include
	// one in its response.
	//
	// See https://datatracker.ietf.org/doc/html/rfc7871#section-7.2.2.
	if ri.ECS != nil {
		err = setECS(resp, ri.ECS, ecsFam, true)
		if err != nil {
			return fmt.Errorf("responding with ecs: %w", err)
		}
	}

	err = rw.WriteMsg(ctx, req, resp)
	if err != nil {
		return fmt.Errorf("writing upstream resp: %w", err)
	}

	return nil
}

// mwHandler implements the [dnsserver.Handler] interface and will be used as a
// [dnsserver.Handler] that Middleware returns from the Wrap function call.
type mwHandler struct {
	mw   *Middleware
	next dnsserver.Handler
}

// type check
var _ dnsserver.Handler = (*mwHandler)(nil)

// ServeDNS implements the [dnsserver.Handler] interface for *mwHandler.
func (mh *mwHandler) ServeDNS(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
) (err error) {
	mw := mh.mw
	cr := mw.cacheReqPool.Get()
	defer func() {
		mw.cacheReqPool.Put(cr)
		err = errors.Annotate(err, "ecs-cache: %w")
	}()

	ri := agd.MustRequestInfoFromContext(ctx)

	cr.host, cr.qType, cr.qClass = ri.Host, ri.QType, ri.QClass
	cr.reqDO = dnsmsg.IsDO(req)

	ecsFam := ecsFamFromReq(ri)

	cr.isECSDeclined = ri.ECS != nil && ri.ECS.Subnet.Bits() == 0
	if cr.isECSDeclined {
		// Don't perform subnet lookup when ECS contains zero-length prefix.
		// Cache key calculation shouldn't consider the subnet of the cache
		// request in this case, but the actual DNS request generated on cache
		// miss will use this data.
		mw.logger.DebugContext(ctx, "explicitly declined ecs")

		cr.subnet = netutil.ZeroPrefix(ecsFam)
	} else {
		loc := locFromReq(ri)
		cr.subnet, err = mw.geoIP.SubnetByLocation(loc, ecsFam)
		if err != nil {
			return fmt.Errorf(
				"getting subnet for country %s (family: %d): %w",
				loc.Country,
				ecsFam,
				err,
			)
		}

		optslog.Trace3(
			ctx,
			mw.logger,
			"request data",
			"ctry", loc.Country,
			"asn", loc.ASN,
			"subnet", cr.subnet,
		)
	}

	// Try getting a cached result using the subnet of the location or zero one
	// when explicitly requested by user.  If there is one, write, increment the
	// metrics, and return.  See also [writeCachedResponse].
	resp, respIsECS := mw.get(ctx, req, cr)
	if resp != nil {
		optslog.Trace1(ctx, mw.logger, "using cached response", "ecs_aware", respIsECS)

		// Increment the hits metrics here, since we already know if the domain
		// name supports ECS or not from the cache data.  Increment the misses
		// metrics in writeUpstreamResponse, where this information is retrieved
		// from the upstream.
		mw.metrics.IncrementLookups(ctx, respIsECS, true)

		// Don't wrap the error, because it's informative enough as is.
		return writeCachedResponse(ctx, rw, req, resp, ri.ECS, ecsFam)
	}

	mw.logger.Log(ctx, slogutil.LevelTrace, "no cached response")

	// Perform an upstream request with the ECS data for the location or zero
	// one on circumstances described above.  If successful, write, increment
	// the metrics, and return.  See also [writeUpstreamResponse].
	ecsReq := mw.cloner.Clone(req)

	err = setECS(ecsReq, &dnsmsg.ECS{
		Subnet: cr.subnet,
		Scope:  0,
	}, ecsFam, false)
	if err != nil {
		return fmt.Errorf("setting ecs for upstream req: %w", err)
	}

	nrw := dnsserver.NewNonWriterResponseWriter(rw.LocalAddr(), rw.RemoteAddr())
	err = mh.next.ServeDNS(ctx, nrw, ecsReq)
	if err != nil {
		return fmt.Errorf("requesting upstream: %w", err)
	}

	resp = nrw.Msg()
	if resp == nil {
		return nil
	}

	// Don't wrap the error, because it's informative enough as is.
	return mw.writeUpstreamResponse(ctx, rw, req, resp, ri, cr, ecsFam)
}

// respIsECSDependent returns true if the response should be considered as ESC
// dependent.
//
// TODO(e.burkov, a.garipov):  Think about ways to mitigate the situation
// where an authoritative nameserver incorrectly echoes our ECS data.
//
// See https://datatracker.ietf.org/doc/html/rfc7871#section-7.2.1.
func respIsECSDependent(scope uint8, fqdn string) (ok bool) {
	if scope == 0 {
		return false
	}

	return !FakeECSFQDNs.Has(fqdn)
}
