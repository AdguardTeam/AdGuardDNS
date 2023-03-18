//go:build linux

package bindtodevice

import (
	"fmt"
	"net"
	"net/netip"
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

// String implements the [net.Addr] interface for *prefixNetAddr.  It returns an
// address of the form "1.2.3.0:56789/24".  That is, IP:port with a subnet after
// a slash.  This is done to make using the IP:port part easier to split off
// using something like [strings.Cut].
func (addr *prefixNetAddr) String() (n string) {
	return fmt.Sprintf(
		"%s/%d",
		netip.AddrPortFrom(addr.prefix.Addr(), addr.port),
		addr.prefix.Bits(),
	)
}

// Network implements the [net.Addr] interface for *prefixNetAddr.
func (addr *prefixNetAddr) Network() (n string) { return addr.network }
