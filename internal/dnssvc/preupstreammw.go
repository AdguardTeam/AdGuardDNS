package dnssvc

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/cache"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/AdguardTeam/AdGuardDNS/internal/ecscache"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// Pre-Upstream Middleware

// preUpstreamMw is a middleware that prepares records for caching and upstream
// handling as well as records anonymous DNS statistics.
type preUpstreamMw struct {
	db           dnsdb.Interface
	geoIP        geoip.Interface
	cacheSize    int
	ecsCacheSize int
	useECSCache  bool
}

// type check
var _ dnsserver.Middleware = (*preUpstreamMw)(nil)

// Wrap implements the [dnsserver.Middleware] interface for *preUpstreamMw.
func (mw *preUpstreamMw) Wrap(h dnsserver.Handler) (wrapped dnsserver.Handler) {
	// Make sure that cache middleware is the closest one to the actual upstream
	// handler.
	if mw.cacheSize > 0 {
		var cacheMw dnsserver.Middleware
		if mw.useECSCache {
			cacheMw = ecscache.NewMiddleware(&ecscache.MiddlewareConfig{
				GeoIP:   mw.geoIP,
				Size:    mw.cacheSize,
				ECSSize: mw.ecsCacheSize,
			})
		} else {
			cacheMw = cache.NewMiddleware(&cache.MiddlewareConfig{
				MetricsListener: &prometheus.CacheMetricsListener{},
				Size:            mw.cacheSize,
			})
		}

		h = cacheMw.Wrap(h)
	}

	log.Info("cache: size: %d, ecs: %t", mw.cacheSize, mw.useECSCache)

	return &preUpstreamMwHandler{
		mw:   mw,
		next: h,
	}
}

// preUpstreamMwHandler implements the [dnsserver.Handler] interface and will
// be used as a [dnsserver.Handler] that the preUpstreamMw middleware returns
// from the Wrap function call.
type preUpstreamMwHandler struct {
	mw   *preUpstreamMw
	next dnsserver.Handler
}

// type check
var _ dnsserver.Handler = (*preUpstreamMwHandler)(nil)

// ServeDNS implements the [dnsserver.Handler] interface for
// *preUpstreamMwHandler.
func (mh *preUpstreamMwHandler) ServeDNS(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
) (err error) {
	defer func() { err = errors.Annotate(err, "pre-upstream mw: %w") }()

	if rn := agdnet.AndroidMetricDomainReplacement(req.Question[0].Name); rn != "" {
		// Don't wrap the error, because it's informative enough as is.
		return mh.serveAndroidMetric(ctx, mh.next, rw, req, rn)
	}

	nwrw := makeNonWriter(rw)
	err = mh.next.ServeDNS(ctx, nwrw, req)
	if err != nil {
		// Don't wrap the error, because this is the main flow, and there is
		// already errors.Annotate here.
		return err
	}

	resp := nwrw.Msg()
	ri := agd.MustRequestInfoFromContext(ctx)
	mh.mw.db.Record(ctx, resp, ri)

	err = rw.WriteMsg(ctx, req, resp)
	if err != nil {
		return fmt.Errorf("writing response: %w", err)
	}

	return nil
}

// serveAndroidMetric makes sure we avoid resolving random Android DoT, DoH metric
// domains.  replName is the replacement domain name to use to improve caching
// of these metric domains.
func (mh *preUpstreamMwHandler) serveAndroidMetric(
	ctx context.Context,
	h dnsserver.Handler,
	rw dnsserver.ResponseWriter,
	origReq *dns.Msg,
	replName string,
) (err error) {
	defer func() { err = errors.Annotate(err, "android metrics: %w") }()

	req := dnsmsg.Clone(origReq)
	req.Question[0].Name = replName

	nwrw := makeNonWriter(rw)
	err = h.ServeDNS(ctx, nwrw, req)
	if err != nil {
		// Don't wrap the error, because this is the main flow, and there is
		// already errors.Annotate here.
		return err
	}

	resp := nwrw.Msg()
	resp.SetReply(origReq)
	mh.replaceResp(origReq.Question[0].Name, resp)

	err = rw.WriteMsg(ctx, origReq, resp)
	if err != nil {
		return fmt.Errorf("writing response: %w", err)
	}

	return nil
}

// replaceResp replaces the name of the answers in resp with name.  This is
// required since all Android metrics requests are cached as one.
func (mh *preUpstreamMwHandler) replaceResp(name string, resp *dns.Msg) {
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
