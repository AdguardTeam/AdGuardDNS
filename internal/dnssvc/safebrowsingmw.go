package dnssvc

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// Safe Browsing Hash Middleware

// safeBrowsingHashMw is a middleware that handles TXT queries for sites that
// may be filtered by safe browsing or parental control filters.
type safeBrowsingHashMw struct {
	// messages is used to construct TXT responses.
	messages *dnsmsg.Constructor

	// filter is the safe browsing DNS filter.
	filter *filter.SafeBrowsingServer
}

// Wrap implements the dnsserver.Middleware interface for *safeBrowsingHashMw.
func (mw *safeBrowsingHashMw) Wrap(h dnsserver.Handler) (wrapped dnsserver.Handler) {
	f := func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) (err error) {
		defer func() { err = errors.Annotate(err, "safe browsing txt mw: %w") }()

		q := req.Question[0]
		qt := q.Qtype

		if qt != dns.TypeTXT {
			err = h.ServeDNS(ctx, rw, req)
			if err != nil {
				// Don't wrap the error, because this is the main flow, and
				// there is already errors.Annotate here.
				return err
			}

			return nil
		}

		host := agd.MustRequestInfoFromContext(ctx).Host

		log.Debug("safe browsing: got txt req for %q", host)

		hashes, matched, err := mw.filter.Hashes(ctx, host)
		if err != nil {
			// Don't return or collect this error to prevent DDoS of the error
			// collector by sending bad requests.
			log.Error("safe browsing mw: matching hashes: %s", err)

			resp := mw.messages.NewMsgREFUSED(req)
			err = rw.WriteMsg(ctx, req, resp)
			if err != nil {
				return fmt.Errorf("writing refused response: %w", err)
			}

			return nil
		} else if !matched {
			err = h.ServeDNS(ctx, rw, req)
			if err != nil {
				// Don't wrap the error, because this is the main flow, and
				// there is already errors.Annotate here.
				return err
			}

			return nil
		}

		resp, err := mw.messages.NewTXTRespMsg(req, hashes...)
		if err != nil {
			// Technically should never happen since the only error that could
			// arise in NewTXTRespMsg is the one about request type mismatch.
			return fmt.Errorf("creating safe browsing result: %w", err)
		}

		log.Debug("safe browsing: writing hashes %q", hashes)

		err = rw.WriteMsg(ctx, req, resp)
		if err != nil {
			return fmt.Errorf("writing response: %w", err)
		}

		return nil
	}

	return dnsserver.HandlerFunc(f)
}
