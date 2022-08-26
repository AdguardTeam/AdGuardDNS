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

// androidMetricReplacementFQDN is the host used to rewrite queries to
// domains ending with androidMetricFQDNSuffix.  We do this in order to cache
// all these queries as a single record and save some resources on this.
const androidMetricReplacementFQDN = "00000000-dnsotls-ds.metric.gstatic.com."

// type check
var _ dnsserver.Middleware = (*preUpstreamMw)(nil)

// Wrap implements the dnsserver.Middleware interface for *preUpstreamMw.
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

	f := func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) (err error) {
		defer func() { err = errors.Annotate(err, "pre-upstream mw: %w") }()

		if agdnet.IsAndroidTLSMetricDomain(req.Question[0].Name) {
			// Don't wrap the error, because it's informative enough as is.
			return mw.serveAndroidMetric(ctx, h, rw, req)
		}

		nwrw := makeNonWriter(rw)
		err = h.ServeDNS(ctx, nwrw, req)
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

func (mw *preUpstreamMw) serveAndroidMetric(
	ctx context.Context,
	h dnsserver.Handler,
	rw dnsserver.ResponseWriter,
	origReq *dns.Msg,
) (err error) {
	defer func() { err = errors.Annotate(err, "android metrics: %w") }()

	req := dnsmsg.Clone(origReq)
	req.Question[0].Name = androidMetricReplacementFQDN

	nwrw := makeNonWriter(rw)
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
func (mw *preUpstreamMw) replaceResp(name string, resp *dns.Msg) {
	if len(resp.Answer) == 0 {
		return
	}

	// TODO(a.garipov): Add Ns and Extra handling as well?
	for _, a := range resp.Answer {
		h := a.Header()
		if agdnet.IsAndroidTLSMetricDomain(h.Name) {
			h.Name = name
		}
	}
}
