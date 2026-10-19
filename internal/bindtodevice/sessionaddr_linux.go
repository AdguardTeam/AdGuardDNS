//go:build linux

package bindtodevice

import (
	"net"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/netutil"
)

// sessionAddr is a wrapper around a *packetSession making it suitable for use
// as a [net.Addr].  This is done to retain the session information between the
// calls from [chanPacketConn.ReadFrom] and [chanPacketConn.WriteTo] when used
// by quic-go.
type sessionAddr struct {
	// session is the UDP session associated with the address.  It must not be
	// nil.
	session *packetSession
}

// AddrPort converts the remote address of the underlying session to a
// netip.AddrPort.  It can be used by helpers like [netutil.NetAddrToAddrPort].
func (a *sessionAddr) AddrPort() (ap netip.AddrPort) {
	return netutil.NetAddrToAddrPort(a.session.raddr)
}

// type check
var _ net.Addr = (*sessionAddr)(nil)

// Network implements the [net.Addr] interface for *sessionAddr.
func (a *sessionAddr) Network() (n string) { return a.session.raddr.Network() }

// String implements the [net.Addr] interface for *sessionAddr.
func (a *sessionAddr) String() (s string) { return a.session.raddr.String() }

// type check
var _ netext.PacketSessionGetter = (*sessionAddr)(nil)

// PacketSession implements the [netext.PacketSessionGetter] interface for
// *sessionAddr.
func (a *sessionAddr) PacketSession() (s netext.PacketSession) { return a.session }
