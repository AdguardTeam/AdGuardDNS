package dnssvc

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// Pre-service middleware

// preServiceMw is a middleware that comes right before the main filtering
// middleware of DNS service.  It includes handling of TXT queries for domain
// names that may be filtered by safe browsing or parental control filters as
// well as handling of the DNS-server check queries.
type preServiceMw struct {
	// messages is used to construct TXT responses.
	messages *dnsmsg.Constructor

	// filter is the safe browsing DNS filter.
	filter *filter.SafeBrowsingServer

	// checker is used to detect and process DNS-check requests.
	checker dnscheck.Interface
}

// type check
var _ dnsserver.Middleware = (*preServiceMw)(nil)

// Wrap implements the [dnsserver.Middleware] interface for *preServiceMw.
func (mw *preServiceMw) Wrap(h dnsserver.Handler) (wrapped dnsserver.Handler) {
	return &preServiceMwHandler{
		mw:   mw,
		next: h,
	}
}

// preServiceMwHandler implements the [dnsserver.Handler] interface and will be
// used as a [dnsserver.Handler] that the preServiceMw middleware returns from
// the Wrap function call.
type preServiceMwHandler struct {
	mw   *preServiceMw
	next dnsserver.Handler
}

// type check
var _ dnsserver.Handler = (*preServiceMwHandler)(nil)

// ServeDNS implements the [dnsserver.Handler] interface for
// *preServiceMwHandler.
func (mh *preServiceMwHandler) ServeDNS(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
) (err error) {
	defer func() { err = errors.Annotate(err, "presvc mw: %w") }()

	ri := agd.MustRequestInfoFromContext(ctx)
	if ri.QType == dns.TypeTXT {
		// Don't wrap the error, because it's informative enough as is.
		return mh.respondWithHashes(ctx, rw, req, ri)
	}

	resp, err := mh.mw.checker.Check(ctx, req, ri)
	if err != nil {
		return fmt.Errorf("calling dnscheck: %w", err)
	} else if resp != nil {
		return errors.Annotate(rw.WriteMsg(ctx, req, resp), "writing dnscheck response: %w")
	}

	// Don't wrap the error, because this is the main flow, and there is already
	// [errors.Annotate] here.
	return mh.next.ServeDNS(ctx, rw, req)
}

// respondWithHashes collects the hashes that match the given hash-prefix query
// and writes a response with them.
func (mh *preServiceMwHandler) respondWithHashes(
	ctx context.Context,
	rw dnsserver.ResponseWriter,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (err error) {
	optlog.Debug1("presvc mw: safe browsing: got txt req for %q", ri.Host)

	hashes, matched, err := mh.mw.filter.Hashes(ctx, ri.Host)
	if err != nil {
		// Don't return or collect this error to prevent DDoS of the error
		// collector by sending bad requests.
		log.Error("presvc mw: safe browsing: matching hashes: %s", err)

		resp := mh.mw.messages.NewMsgREFUSED(req)
		err = rw.WriteMsg(ctx, req, resp)

		return errors.Annotate(err, "writing refused response: %w")
	} else if !matched {
		// Don't wrap the error, because this is the main flow, and there is
		// already [errors.Annotate] here.
		return mh.next.ServeDNS(ctx, rw, req)
	}

	resp, err := mh.mw.messages.NewTXTRespMsg(req, hashes...)
	if err != nil {
		// Technically should never happen since the only error that could arise
		// in [dnsmsg.Constructor.NewTXTRespMsg] is the one about request type
		// mismatch.
		return fmt.Errorf("creating safe browsing result: %w", err)
	}

	optlog.Debug1("presvc mw: safe browsing: writing hashes %q", hashes)

	err = rw.WriteMsg(ctx, req, resp)
	if err != nil {
		return fmt.Errorf("writing safe browsing response: %w", err)
	}

	return nil
}
