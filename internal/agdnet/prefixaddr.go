package agdnet

import (
	"fmt"
	"net"
	"net/netip"
)

// PrefixNetAddr is a wrapper around netip.Prefix that makes it a [net.Addr].
type PrefixNetAddr struct {
	Prefix netip.Prefix
	Net    string
	Port   uint16
}

// type check
var _ net.Addr = (*PrefixNetAddr)(nil)

// String implements the [net.Addr] interface for *PrefixNetAddr.  It returns
// either a simple IP:port address or one with the prefix length appended after
// a slash, depending on whether or not subnet is a single-address subnet.  This
// is done to make using the IP:port part easier to split off using functions
// like [strings.Cut].
func (addr *PrefixNetAddr) String() (n string) {
	p := addr.Prefix
	addrPort := netip.AddrPortFrom(p.Addr(), addr.Port)
	if p.IsSingleIP() {
		return addrPort.String()
	}

	return fmt.Sprintf("%s/%d", addrPort, p.Bits())
}

// Network implements the [net.Addr] interface for *PrefixNetAddr.
func (addr *PrefixNetAddr) Network() (n string) { return addr.Net }
