//go:build linux

package bindtodevice

import (
	"context"
	"net"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
)

// chanListenConfig is a [netext.ListenConfig] implementation that uses the
// provided channel-based packet connection and listener to implement the
// methods of the interface.
//
// netext.ListenConfig instances of this type are the ones that are going to be
// set as [dnsserver.ConfigBase.ListenConfig] to make the bind-to-device logic
// work.
type chanListenConfig struct {
	packetConn *chanPacketConn
	listener   *chanListener
}

// type check
var _ netext.ListenConfig = (*chanListenConfig)(nil)

// Listen implements the [netext.ListenConfig] interface for *chanListenConfig.
func (lc *chanListenConfig) Listen(
	ctx context.Context,
	network string,
	address string,
) (l net.Listener, err error) {
	return lc.listener, nil
}

// ListenPacket implements the [netext.ListenConfig] interface for
// *chanListenConfig.
func (lc *chanListenConfig) ListenPacket(
	ctx context.Context,
	network string,
	address string,
) (c net.PacketConn, err error) {
	return lc.packetConn, nil
}
