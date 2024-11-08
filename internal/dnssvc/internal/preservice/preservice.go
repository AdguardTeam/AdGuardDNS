// Package preservice contains the middleware that comes right before the main
// filtering middleware of DNS service.
package preservice

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/optslog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
)

// Middleware is a middleware that comes right before the main filtering
// middleware of DNS service.  It includes handling of TXT queries for domain
// names that may be filtered by safe browsing or parental control filters as
// well as handling of the DNS-server check queries.
type Middleware struct {
	logger      *slog.Logger
	messages    *dnsmsg.Constructor
	hashMatcher filter.HashMatcher
	checker     dnscheck.Interface
}

// Config is the configurational structure for the preservice middleware.  All
// fields must be non-nil.
type Config struct {
	// Logger is used to log the operation of the middleware.
	Logger *slog.Logger

	// Messages is used to construct TXT responses.
	Messages *dnsmsg.Constructor

	// HashMatcher is the safe browsing DNS hashMatcher.
	HashMatcher filter.HashMatcher

	// Checker is used to detect and process DNS-check requests.
	Checker dnscheck.Interface
}

// New returns a new preservice middleware.  c must not be nil.
func New(c *Config) (mw *Middleware) {
	return &Middleware{
		logger:      c.Logger,
		messages:    c.Messages,
		hashMatcher: c.HashMatcher,
		checker:     c.Checker,
	}
}

// type check
var _ dnsserver.Middleware = (*Middleware)(nil)

// Wrap implements the [dnsserver.Middleware] interface for *Middleware.
func (mw *Middleware) Wrap(next dnsserver.Handler) (wrapped dnsserver.Handler) {
	f := func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) (err error) {
		defer func() { err = errors.Annotate(err, "presvcmw: %w") }()

		ri := agd.MustRequestInfoFromContext(ctx)
		if ri.QType == dns.TypeTXT {
			// Don't wrap the error, because it's informative enough as is.
			return mw.respondWithHashes(ctx, next, rw, req, ri)
		}

		resp, err := mw.checker.Check(ctx, req, ri)
		if err != nil {
			return fmt.Errorf("calling dnscheck: %w", err)
		}

		if resp == nil {
			// Don't wrap the error, because this is the main flow, and there is
			// already [errors.Annotate] here.
			return next.ServeDNS(ctx, rw, req)
		}

		err = rw.WriteMsg(ctx, req, resp)
		if err != nil {
			return fmt.Errorf("writing dnscheck response: %w", err)
		}

		return nil
	}

	return dnsserver.HandlerFunc(f)
}

// respondWithHashes collects the hashes that match the given hash-prefix query
// and writes a response with them.
func (mw *Middleware) respondWithHashes(
	ctx context.Context,
	next dnsserver.Handler,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (err error) {
	optslog.Debug1(ctx, mw.logger, "got txt req", "host", ri.Host)

	hashes, matched, err := mw.hashMatcher.MatchByPrefix(ctx, ri.Host)
	if err != nil {
		// Don't return or collect this error to prevent DDoS of the error
		// collector by sending bad requests.
		mw.logger.ErrorContext(
			ctx,
			"matching hashes",
			slogutil.KeyError, err,
		)

		resp := mw.messages.NewRespRCode(req, dns.RcodeRefused)
		err = rw.WriteMsg(ctx, req, resp)

		return errors.Annotate(err, "writing refused response: %w")
	} else if !matched {
		// Don't wrap the error, because this is the main flow, and there is
		// already [errors.Annotate] here.
		return next.ServeDNS(ctx, rw, req)
	}

	resp, err := mw.messages.NewRespTXT(req, hashes...)
	if err != nil {
		// Technically should never happen since the only error that could arise
		// in [dnsmsg.Constructor.NewTXTRespMsg] is the one about request type
		// mismatch.
		return fmt.Errorf("creating safe browsing result: %w", err)
	}

	optslog.Debug1(ctx, mw.logger, "writing hashes", "hashes", hashes)

	err = rw.WriteMsg(ctx, req, resp)
	if err != nil {
		return fmt.Errorf("writing safe browsing response: %w", err)
	}

	return nil
}
