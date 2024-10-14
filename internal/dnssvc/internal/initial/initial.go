// Package initial contains the initial, outermost (except for ratelimit/access)
// middleware of the AdGuard DNS server.  It handles Firefox canary hosts
// requests, sets and resets the AD bit for further processing, as well as
// handles some special domains.
//
// TODO(a.garipov):  Consider renaming the package into specialdomainmw or
// merging with another middleware.
package initial

import (
	"context"
	"log/slog"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/optslog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
)

// Middleware is the initial middleware of the AdGuard DNS server.  This
// middleware must be the most outer middleware apart from the ratelimit/access
// middleware.
type Middleware struct {
	logger *slog.Logger
}

// Config is the configuration structure for the initial middleware.  All fields
// must be non-nil.
type Config struct {
	// Logger is used to log the operation of the middleware.
	Logger *slog.Logger
}

// New returns a new initial middleware.  c must not be nil, and all its fields
// must be valid.
func New(c *Config) (mw *Middleware) {
	return &Middleware{
		logger: c.Logger,
	}
}

// type check
var _ dnsserver.Middleware = (*Middleware)(nil)

// Wrap implements the [dnsserver.Middleware] interface for *Middleware
func (mw *Middleware) Wrap(next dnsserver.Handler) (wrapped dnsserver.Handler) {
	f := func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) (err error) {
		defer func() { err = errors.Annotate(err, "init mw: %w") }()

		// Save the actual value of the request AD and DO bits and set the AD
		// bit in the request to true, so that the upstream validates the data
		// and caches the actual value of the response AD bit.  Restore it
		// later, depending on the request and response data.
		reqAD := req.AuthenticatedData
		reqDO := dnsmsg.IsDO(req)
		req.AuthenticatedData = true

		ri := agd.MustRequestInfoFromContext(ctx)

		if specHdlr, name := mw.reqInfoSpecialHandler(ri); specHdlr != nil {
			optslog.Debug1(ctx, mw.logger, "using req-info special handler", "name", name)

			// Don't wrap the error, because it's informative enough as is, and
			// because if handled is true, the main flow terminates here.
			return specHdlr(ctx, rw, req, ri)
		}

		// Record the response, restore the AD bit value in both the request and
		// the response, and write the response.
		nwrw := internal.MakeNonWriter(rw)
		err = next.ServeDNS(ctx, nwrw, req)
		if err != nil {
			// Don't wrap the error, because this is the main flow, and there is
			// already errors.Annotate here.
			return err
		}

		resp := nwrw.Msg()

		// Following RFC 6840, set the AD bit in the response only when the
		// response is authenticated, and the request contained either a set DO
		// bit or a set AD bit.
		//
		// See https://datatracker.ietf.org/doc/html/rfc6840#section-5.8.
		resp.AuthenticatedData = resp.AuthenticatedData && (reqAD || reqDO)

		err = rw.WriteMsg(ctx, req, resp)

		return errors.Annotate(err, "writing resp: %w")
	}

	return dnsserver.HandlerFunc(f)
}
