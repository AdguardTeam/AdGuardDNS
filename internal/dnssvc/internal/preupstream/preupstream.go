// Package preupstream contains the middleware that records anonymous DNS
// statistics.
//
// TODO(a.garipov):  Consider merging with mainmw if not expanded.
package preupstream

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
)

// Middleware is a middleware that prepares records for caching and upstream
// handling as well as records anonymous DNS statistics.
type Middleware struct {
	db dnsdb.Interface
}

// Config is the configuration structure for the preupstream middleware.
type Config struct {
	// DB is used to update anonymous statistics about DNS queries.  It must not
	// be nil.
	DB dnsdb.Interface
}

// New returns a new preupstream middleware.  c must not be nil.
func New(ctx context.Context, c *Config) (mw *Middleware) {
	return &Middleware{
		db: c.DB,
	}
}

// type check
var _ dnsserver.Middleware = (*Middleware)(nil)

// Wrap implements the [dnsserver.Middleware] interface for *Middleware.
func (mw *Middleware) Wrap(next dnsserver.Handler) (wrapped dnsserver.Handler) {
	f := func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) (err error) {
		defer func() { err = errors.Annotate(err, "preupstreammw: %w") }()

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
