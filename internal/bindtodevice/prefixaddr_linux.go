//go:build linux

package bindtodevice

import (
	"net"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
)

// prefixNetAddr is a wrapper around netip.Prefix that makes it a [net.Addr].
//
// TODO(a.garipov): Support port 0, which will probably require atomic
// operations and assistance in [Manager.Start].
type prefixNetAddr struct {
	prefix  netip.Prefix
	network string
	port    uint16
}

// type check
var _ net.Addr = (*prefixNetAddr)(nil)

// String implements the [net.Addr] interface for *prefixNetAddr.
//
// See [agdnet.FormatPrefixAddr] for the format.
func (addr *prefixNetAddr) String() (n string) {
	return agdnet.FormatPrefixAddr(addr.prefix, addr.port)
}

// Network implements the [net.Addr] interface for *prefixNetAddr.
func (addr *prefixNetAddr) Network() (n string) { return addr.network }
