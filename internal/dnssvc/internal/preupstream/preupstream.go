// Package preupstream contains the middleware that prepares records for
// upstream handling and caches them, as well as records anonymous DNS
// statistics.
package preupstream

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/cache"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/ecscache"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// Middleware is a middleware that prepares records for caching and upstream
// handling as well as records anonymous DNS statistics.
type Middleware struct {
	cloner              *dnsmsg.Cloner
	db                  dnsdb.Interface
	geoIP               geoip.Interface
	cacheMinTTL         time.Duration
	cacheSize           int
	ecsCacheSize        int
	useECSCache         bool
	useCacheTTLOverride bool
}

// Config is the configurational structure for the preupstream middleware.  DB
// must not be nil.
type Config struct {
	// Cloner is used to clone messages taken from cache.
	Cloner *dnsmsg.Cloner

	// DB is used to update anonymous statistics about DNS queries.
	DB dnsdb.Interface

	// GeoIP is the GeoIP database used to detect geographic data about IP
	// addresses in requests and responses.
	GeoIP geoip.Interface

	// CacheMinTTL is the minimum supported TTL for cache items.
	CacheMinTTL time.Duration

	// CacheSize is the size of the DNS cache for domain names that don't
	// support ECS.
	CacheSize int

	// ECSCacheSize is the size of the DNS cache for domain names that support
	// ECS.
	ECSCacheSize int

	// UseECSCache shows if the EDNS Client Subnet (ECS) aware cache should be
	// used.
	UseECSCache bool

	// UseCacheTTLOverride shows if the TTL overrides logic should be used.
	UseCacheTTLOverride bool
}

// New returns a new preupstream middleware.  c must not be nil.
func New(c *Config) (mw *Middleware) {
	return &Middleware{
		cloner:              c.Cloner,
		db:                  c.DB,
		geoIP:               c.GeoIP,
		cacheMinTTL:         c.CacheMinTTL,
		cacheSize:           c.CacheSize,
		ecsCacheSize:        c.ECSCacheSize,
		useECSCache:         c.UseECSCache,
		useCacheTTLOverride: c.UseCacheTTLOverride,
	}
}

// type check
var _ dnsserver.Middleware = (*Middleware)(nil)

// Wrap implements the [dnsserver.Middleware] interface for *Middleware.
func (mw *Middleware) Wrap(next dnsserver.Handler) (wrapped dnsserver.Handler) {
	next = mw.wrapCacheMw(next)

	f := func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) (err error) {
		defer func() { err = errors.Annotate(err, "preupstream mw: %w") }()

		if rn := agdnet.AndroidMetricDomainReplacement(req.Question[0].Name); rn != "" {
			// Don't wrap the error, because it's informative enough as is.
			return mw.serveAndroidMetric(ctx, next, rw, req, rn)
		}

		nwrw := internal.MakeNonWriter(rw)
		err = next.ServeDNS(ctx, nwrw, req)
		if err != nil {
			// Don't wrap the error, because this is the main flow, and there is
			// already errors.Annotate here.
			return err
		}

		resp := nwrw.Msg()
		ri := agd.MustRequestInfoFromContext(ctx)
		mw.db.Record(ctx, resp, ri)

		err = rw.WriteMsg(ctx, req, resp)
		if err != nil {
			return fmt.Errorf("writing response: %w", err)
		}

		return nil
	}

	return dnsserver.HandlerFunc(f)
}

// wrapCacheMw does nothing if cacheSize is zero otherwise returns wrapped
// handler with caching middleware which is ECS-aware or not.
//
// TODO(s.chzhen):  Consider separating caching middleware.
func (mw *Middleware) wrapCacheMw(next dnsserver.Handler) (wrapped dnsserver.Handler) {
	log.Info("cache: size: %d, ecs: %t", mw.cacheSize, mw.useECSCache)

	if mw.cacheSize == 0 {
		return next
	}

	var cacheMw dnsserver.Middleware
	if mw.useECSCache {
		cacheMw = ecscache.NewMiddleware(&ecscache.MiddlewareConfig{
			Cloner:         mw.cloner,
			GeoIP:          mw.geoIP,
			Size:           mw.cacheSize,
			ECSSize:        mw.ecsCacheSize,
			MinTTL:         mw.cacheMinTTL,
			UseTTLOverride: mw.useCacheTTLOverride,
		})
	} else {
		cacheMw = cache.NewMiddleware(&cache.MiddlewareConfig{
			MetricsListener: &prometheus.CacheMetricsListener{},
			Size:            mw.cacheSize,
			MinTTL:          mw.cacheMinTTL,
			UseTTLOverride:  mw.useCacheTTLOverride,
		})
	}

	return cacheMw.Wrap(next)
}

// serveAndroidMetric makes sure we avoid resolving random Android DoT, DoH
// metric domains.  replName is the replacement domain name to use to improve
// caching of these metric domains.
func (mw *Middleware) serveAndroidMetric(
	ctx context.Context,
	h dnsserver.Handler,
	rw dnsserver.ResponseWriter,
	origReq *dns.Msg,
	replName string,
) (err error) {
	defer func() { err = errors.Annotate(err, "android metrics: %w") }()

	req := dnsmsg.Clone(origReq)
	req.Question[0].Name = replName

	nwrw := internal.MakeNonWriter(rw)
	err = h.ServeDNS(ctx, nwrw, req)
	if err != nil {
		// Don't wrap the error, because this is the main flow, and there is
		// already errors.Annotate here.
		return err
	}

	resp := nwrw.Msg()
	resp.SetReply(origReq)
	mw.replaceResp(origReq.Question[0].Name, resp)

	err = rw.WriteMsg(ctx, origReq, resp)
	if err != nil {
		return fmt.Errorf("writing response: %w", err)
	}

	return nil
}

// replaceResp replaces the name of the answers in resp with name.  This is
// required since all Android metrics requests are cached as one.
func (mw *Middleware) replaceResp(name string, resp *dns.Msg) {
	if len(resp.Answer) == 0 {
		return
	}

	// TODO(a.garipov): Add Ns and Extra handling as well?
	for _, a := range resp.Answer {
		h := a.Header()
		if agdnet.AndroidMetricDomainReplacement(h.Name) != "" {
			h.Name = name
		}
	}
}
