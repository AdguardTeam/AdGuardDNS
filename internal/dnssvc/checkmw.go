package dnssvc

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
)

// DNS Checker Middleware

// checkMw is a middleware that records DNS statistics.
type checkMw struct {
	checker dnscheck.Interface
}

// type check
var _ dnsserver.Middleware = (*checkMw)(nil)

// Wrap implements the dnsserver.Middleware interface for *checkMw.
func (mw *checkMw) Wrap(h dnsserver.Handler) (wrapped dnsserver.Handler) {
	f := func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) (err error) {
		defer func() { err = errors.Annotate(err, "dnscheck mw: %w") }()

		ri := agd.MustRequestInfoFromContext(ctx)
		resp, err := mw.checker.Check(ctx, req, ri)
		if err != nil {
			return err
		} else if resp == nil {
			return h.ServeDNS(ctx, rw, req)
		}

		err = rw.WriteMsg(ctx, req, resp)
		if err != nil {
			return fmt.Errorf("writing response: %w", err)
		}

		return nil
	}

	return dnsserver.HandlerFunc(f)
}
