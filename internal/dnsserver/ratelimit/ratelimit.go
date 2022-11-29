// Package ratelimit contains rate limiting interfaces and utilities.
package ratelimit

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// Rate Limiting Types

// Interface represents a rate limiter that allows or denies queries for the IP
// address.  All methods must be safe for concurrent use.
type Interface interface {
	IsRateLimited(ctx context.Context, req *dns.Msg, ip netip.Addr) (drop, allowlisted bool, err error)
	CountResponses(ctx context.Context, resp *dns.Msg, ip netip.Addr)
}

// Middleware applies rate limiting to DNS queries.
type Middleware struct {
	// Metrics is a listener for the middleware events.  Set it if you want to
	// keep track of what the middleware does and record performance metrics.
	//
	// TODO(ameshkov): consider moving ALL MetricsListeners to constructors
	Metrics MetricsListener

	// rateLimit is defines whether the query should be dropped or not.  The
	// default implementation of it is [*BackOff].
	rateLimit Interface

	// protos is a list of protocols this middleware applies rate-limiting logic
	// to.  If empty, it applies to all protocols.
	protos []dnsserver.Protocol
}

// type check
var _ dnsserver.Middleware = (*Middleware)(nil)

// NewMiddleware returns a properly initialized [*Middleware].  protos is a list
// of [dnsserver.Protocol] the rate limit will be used for.
func NewMiddleware(rl Interface, protos []dnsserver.Protocol) (m *Middleware, err error) {
	return &Middleware{
		Metrics:   &EmptyMetricsListener{},
		protos:    protos,
		rateLimit: rl,
	}, nil
}

// Wrap implements the [dnsserver.Middleware] interface for [*Middleware].
func (m *Middleware) Wrap(handler dnsserver.Handler) (wrapped dnsserver.Handler) {
	f := func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) (err error) {
		if !m.isEnabledForProto(ctx) {
			return handler.ServeDNS(ctx, rw, req)
		}

		raddr := rw.RemoteAddr()
		addrPort := netutil.NetAddrToAddrPort(raddr)
		if addrPort.Port() == 0 {
			// Probably spoofing.  Return immediately.
			m.Metrics.OnRateLimited(ctx, req, rw)

			return nil
		}

		ip := addrPort.Addr()
		drop, allowlisted, err := m.rateLimit.IsRateLimited(ctx, req, ip)
		if err != nil {
			return fmt.Errorf("ratelimit mw: %w", err)
		} else if drop {
			m.Metrics.OnRateLimited(ctx, req, rw)

			return nil
		} else if allowlisted {
			// If the request is allowlisted, we can pass it through to the
			// next handler immediately.
			m.Metrics.OnAllowlisted(ctx, req, rw)

			return handler.ServeDNS(ctx, rw, req)
		}

		nwrw := dnsserver.NewNonWriterResponseWriter(rw.LocalAddr(), raddr)
		err = handler.ServeDNS(ctx, nwrw, req)
		if err != nil {
			return err
		}

		resp := nwrw.Msg()
		if resp == nil {
			return nil
		}

		m.rateLimit.CountResponses(ctx, resp, ip)

		return rw.WriteMsg(ctx, req, resp)
	}

	return dnsserver.HandlerFunc(f)
}

// isEnabledForProto returns true if m is configured to ratelimit the protocol
// given in ctx.
func (m *Middleware) isEnabledForProto(ctx context.Context) (enabled bool) {
	if len(m.protos) == 0 {
		return true
	}

	si := dnsserver.MustServerInfoFromContext(ctx)

	for _, proto := range m.protos {
		if proto == si.Proto {
			return true
		}
	}

	return enabled
}
