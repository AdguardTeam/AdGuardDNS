// Package ecscache implements a EDNS Client Subnet (ECS) aware DNS cache that
// can be used as a [dnsserver.Middleware].
package ecscache

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

// Constants that define cache identifiers for the cache manager.
const (
	cachePrefix    = "dns/"
	cacheIDWithECS = cachePrefix + "ecscache_with_ecs"
	cacheIDNoECS   = cachePrefix + "ecscache_no_ecs"
)

// Middleware is a dnsserver.Middleware with ECS-aware caching.
type Middleware struct {
	// cloner is the memory-efficient cloner of DNS messages.
	cloner *dnsmsg.Cloner

	// cache is the LRU cache for results indicating no support for ECS.
	cache agdcache.Interface[uint64, *cacheItem]

	// ecsCache is the LRU cache for results indicating ECS support.
	ecsCache agdcache.Interface[uint64, *cacheItem]

	// geoIP is used to get subnets for countries.
	geoIP geoip.Interface

	// cacheReqPool is a pool of cache requests.
	cacheReqPool *syncutil.Pool[cacheRequest]

	// cacheMinTTL is the minimum supported TTL for cache items.
	cacheMinTTL time.Duration

	// useTTLOverride shows if the TTL overrides logic should be used.
	useTTLOverride bool
}

// MiddlewareConfig is the configuration structure for NewMiddleware.
type MiddlewareConfig struct {
	// Cloner is used to clone messages taken from cache.
	Cloner *dnsmsg.Cloner

	// CacheManager is the global cache manager.  CacheManager must not be nil.
	CacheManager agdcache.Manager

	// GeoIP is the GeoIP database used to get subnets for countries.  It must
	// not be nil.
	GeoIP geoip.Interface

	// MinTTL is the minimum supported TTL for cache items.
	MinTTL time.Duration

	// Size is the number of entities to hold in the cache for hosts that don't
	// support ECS.  It must be greater than zero.
	Size int

	// ECSSize is the number of entities to hold in the cache for hosts that
	// support ECS.  It must be greater than zero.
	ECSSize int

	// UseTTLOverride shows if the TTL overrides logic should be used.
	UseTTLOverride bool
}

// NewMiddleware initializes a new ECS-aware LRU caching middleware.  It also
// adds the caches with IDs [CacheIDNoECS] and [CacheIDWithECS] to the cache
// manager.  c must not be nil.
func NewMiddleware(c *MiddlewareConfig) (m *Middleware) {
	cache := agdcache.NewLRU[uint64, *cacheItem](&agdcache.LRUConfig{
		Size: c.Size,
	})
	ecsCache := agdcache.NewLRU[uint64, *cacheItem](&agdcache.LRUConfig{
		Size: c.ECSSize,
	})

	c.CacheManager.Add(cacheIDNoECS, cache)
	c.CacheManager.Add(cacheIDWithECS, ecsCache)

	return &Middleware{
		cloner:   c.Cloner,
		cache:    cache,
		ecsCache: ecsCache,
		geoIP:    c.GeoIP,
		cacheReqPool: syncutil.NewPool(func() (req *cacheRequest) {
			return &cacheRequest{}
		}),
		cacheMinTTL:    c.MinTTL,
		useTTLOverride: c.UseTTLOverride,
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
	respIsECSDependent bool,
) (err error) {
	// Increment the hits metrics here, since we already know if the domain name
	// supports ECS or not from the cache data.  Increment the misses metrics in
	// writeResponse, where this information is retrieved from the upstream
	metrics.ECSCacheLookupTotalHits.Inc()

	metrics.IncrementCond(
		respIsECSDependent,
		metrics.ECSCacheLookupHasSupportHits,
		metrics.ECSCacheLookupNoSupportHits,
	)

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

	// TODO(a.garipov):  Use optslog.Trace2.
	optlog.Debug2("ecscache: upstream: %s/%d", subnet, scope)

	reqDO := cr.reqDO
	rmHopToHopData(resp, ri.QType, reqDO)

	metrics.ECSCacheLookupTotalMisses.Inc()

	respIsECS := respIsECSDependent(scope, req.Question[0].Name)
	if respIsECS {
		metrics.ECSCacheLookupHasSupportMisses.Inc()
		metrics.ECSHasSupportCacheSize.Set(float64(mw.ecsCache.Len()))
	} else {
		metrics.ECSCacheLookupNoSupportMisses.Inc()
		metrics.ECSNoSupportCacheSize.Set(float64(mw.cache.Len()))

		cr.subnet = netutil.ZeroPrefix(ecsFam)
	}

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
		log.Debug("ecscache: explicitly declined ecs")

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

		optlog.Debug3("ecscache: got ctry %s, asn %d, subnet %s", loc.Country, loc.ASN, cr.subnet)
	}

	// Try getting a cached result using the subnet of the location or zero one
	// when explicitly requested by user.  If there is one, write, increment the
	// metrics, and return.  See also [writeCachedResponse].
	resp, respIsECS := mw.get(req, cr)
	if resp != nil {
		optlog.Debug1("ecscache: using cached response (ecs-aware: %t)", respIsECS)

		// Don't wrap the error, because it's informative enough as is.
		return writeCachedResponse(ctx, rw, req, resp, ri.ECS, ecsFam, respIsECS)
	}

	log.Debug("ecscache: no cached response")

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
