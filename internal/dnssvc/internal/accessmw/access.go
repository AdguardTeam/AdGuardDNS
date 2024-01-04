// Package accessmw contains the access middleware of the AdGuard DNS server.
// It filters out the domain scanners and other requests by specified AdBlock
// rules and IP subnets.
package accessmw

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// type check
var _ dnsserver.Middleware = (*Middleware)(nil)

// Middleware is the access middleware of the AdGuard DNS server.
type Middleware struct {
	accessManager access.Interface
}

// Config is the configuration structure for the access middleware.  All fields
// must be non-nil.
type Config struct {
	AccessManager access.Interface
}

// New returns a new access middleware.  c must not be nil.
func New(c *Config) (mw *Middleware) {
	return &Middleware{
		accessManager: c.AccessManager,
	}
}

// type check
var _ dnsserver.Middleware = (*Middleware)(nil)

// Wrap implements the [dnsserver.Middleware] interface for *Middleware
func (mw *Middleware) Wrap(next dnsserver.Handler) (wrapped dnsserver.Handler) {
	f := func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) (err error) {
		defer func() { err = errors.Annotate(err, "access mw: %w") }()

		rAddr := netutil.NetAddrToAddrPort(rw.RemoteAddr()).Addr()
		if blocked, _ := mw.accessManager.IsBlockedIP(rAddr); blocked {
			metrics.AccessBlockedForSubnetTotal.Inc()

			return nil
		}

		// Assume that module dnsserver has already validated that the request
		// always has exactly one question for us.
		q := req.Question[0]
		normalizedDomain := agdnet.NormalizeQueryDomain(q.Name)
		if mw.accessManager.IsBlockedHost(normalizedDomain, q.Qtype) {
			metrics.AccessBlockedForHostTotal.Inc()

			return nil
		}

		return next.ServeDNS(ctx, rw, req)
	}

	return dnsserver.HandlerFunc(f)
}
