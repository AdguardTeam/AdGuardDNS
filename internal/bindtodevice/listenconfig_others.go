//go:build !linux

package bindtodevice

import (
	"context"
	"fmt"
	"net"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
)

// ListenConfig is a [netext.ListenConfig] implementation that uses the
// provided channel-based packet connection and listener to implement the
// methods of the interface.
//
// netext.ListenConfig instances of this type are the ones that are going to be
// set as [dnsserver.ConfigBase.ListenConfig] to make the bind-to-device logic
// work.
//
// It is only supported on Linux.
type ListenConfig struct{}

// type check
var _ netext.ListenConfig = (*ListenConfig)(nil)

// Listen implements the [netext.ListenConfig] interface for *ListenConfig.
//
// It is only supported on Linux.
func (lc *ListenConfig) Listen(
	ctx context.Context,
	network string,
	address string,
) (l net.Listener, err error) {
	return nil, fmt.Errorf(
		"bindtodevice: listen: %w; only supported on linux",
		errors.ErrUnsupported,
	)
}

// ListenPacket implements the [netext.ListenConfig] interface for
// *ListenConfig.
//
// It is only supported on Linux.
func (lc *ListenConfig) ListenPacket(
	ctx context.Context,
	network string,
	address string,
) (c net.PacketConn, err error) {
	return nil, fmt.Errorf(
		"bindtodevice: listenpacket: %w; only supported on linux",
		errors.ErrUnsupported,
	)
}

// Addr returns the address on which lc accepts connections.
//
// It is only supported on Linux.
func (lc *ListenConfig) Addr() (addr *agdnet.PrefixNetAddr) {
	return nil
}
