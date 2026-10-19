package dnsserver

import (
	"context"
	"net"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/messagetap"
	"github.com/AdguardTeam/golibs/netutil"
)

// tapRequest wraps the call to tap.TapRequest with the appropriate parameters.
// All arguments must not be nil.
func tapRequest(
	ctx context.Context,
	now time.Time,
	tap messagetap.Interface,
	laddr net.Addr,
	raddr net.Addr,
	b []byte,
) {
	tap.TapRequest(
		ctx,
		now,
		netutil.NetAddrToAddrPort(laddr),
		netutil.NetAddrToAddrPort(raddr),
		b,
	)
}

// tapResponse wraps the call to tap.TapResponse with the appropriate
// parameters.  All arguments must not be nil.
func tapResponse(
	ctx context.Context,
	now time.Time,
	tap messagetap.Interface,
	laddr net.Addr,
	raddr net.Addr,
	b []byte,
) {
	tap.TapResponse(
		ctx,
		now,
		netutil.NetAddrToAddrPort(laddr),
		netutil.NetAddrToAddrPort(raddr),
		b,
	)
}
