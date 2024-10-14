package ratelimitmw

import (
	"context"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/optslog"
	"github.com/miekg/dns"
)

// isBlockedByAccess returns true if req is blocked by global or profile access
// settings.
func (mw *Middleware) isBlockedByAccess(
	ctx context.Context,
	ri *agd.RequestInfo,
	req *dns.Msg,
	raddr netip.AddrPort,
) (isBlocked bool) {
	// NOTE:  Global access has priority over the profile one.
	if mw.accessManager.IsBlockedIP(raddr.Addr()) {
		mw.metrics.IncrementAccessBlockedBySubnet(ctx)
		optslog.Debug1(ctx, mw.logger, "access denied globally by ip", "remote_ip", ri.RemoteIP)

		return true
	} else if mw.accessManager.IsBlockedHost(ri.Host, ri.QType) {
		mw.metrics.IncrementAccessBlockedByHost(ctx)
		optslog.Debug2(
			ctx,
			mw.logger,
			"access denied globally by rule",
			"remote_ip", ri.RemoteIP,
			"host", ri.Host,
		)

		return true
	}

	p, _ := ri.DeviceData()
	if p == nil {
		return false
	}

	if p.Access.IsBlocked(req, raddr, ri.Location) {
		mw.metrics.IncrementAccessBlockedByProfile(ctx)
		optslog.Debug2(
			ctx,
			mw.logger,
			"access denied by profile",
			"remote_ip", ri.RemoteIP,
			"profile_id", p.ID,
		)

		return true
	}

	return false
}
