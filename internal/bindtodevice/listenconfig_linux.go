//go:build linux

package bindtodevice

import (
	"context"
	"net"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
)

// ListenConfig is a [netext.ListenConfig] implementation that uses the
// provided channel-based packet connection and listener to implement the
// methods of the interface.
//
// netext.ListenConfig instances of this type are the ones that are going to be
// set as [dnsserver.ConfigBase.ListenConfig] to make the bind-to-device logic
// work.
type ListenConfig struct {
	packetConn *chanPacketConn
	listener   *chanListener
	addr       *agdnet.PrefixNetAddr
}

// type check
var _ netext.ListenConfig = (*ListenConfig)(nil)

// Listen implements the [netext.ListenConfig] interface for *ListenConfig.
func (lc *ListenConfig) Listen(
	ctx context.Context,
	network string,
	address string,
) (l net.Listener, err error) {
	return lc.listener, nil
}

// ListenPacket implements the [netext.ListenConfig] interface for
// *ListenConfig.
func (lc *ListenConfig) ListenPacket(
	ctx context.Context,
	network string,
	address string,
) (c net.PacketConn, err error) {
	return lc.packetConn, nil
}

// Addr returns the address on which lc accepts connections.  addr.Net is empty.
func (lc *ListenConfig) Addr() (addr *agdnet.PrefixNetAddr) {
	return lc.addr
}
