package dnsserver

import (
	"context"
	"net"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/messagetap"
	"github.com/AdguardTeam/golibs/netutil"
)

// tapRequest wraps the call to tap.TapRequest with the appropriate parameters.
// All arguments must not be nil.
func tapRequest(ctx context.Context, tap messagetap.Interface, laddr, raddr net.Addr, b []byte) {
	tap.TapRequest(
		ctx,
		netutil.NetAddrToAddrPort(laddr),
		netutil.NetAddrToAddrPort(raddr),
		b,
	)
}

// tapResponse wraps the call to tap.TapResponse with the appropriate
// parameters.  All arguments must not be nil.
func tapResponse(ctx context.Context, tap messagetap.Interface, laddr, raddr net.Addr, b []byte) {
	tap.TapResponse(
		ctx,
		netutil.NetAddrToAddrPort(laddr),
		netutil.NetAddrToAddrPort(raddr),
		b,
	)
}
