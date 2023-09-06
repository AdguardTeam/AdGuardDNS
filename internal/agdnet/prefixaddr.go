package agdnet

import (
	"fmt"
	"net/netip"
)

// FormatPrefixAddr returns either a simple IP:port address or one with the
// prefix length appended after a slash, depending on whether or not subnet is a
// single-address subnet.  This is done to make using the IP:port part easier to
// split off using functions like [strings.Cut].
func FormatPrefixAddr(subnet netip.Prefix, port uint16) (s string) {
	addrPort := netip.AddrPortFrom(subnet.Addr(), port)
	if subnet.IsSingleIP() {
		return addrPort.String()
	}

	return fmt.Sprintf("%s/%d", addrPort, subnet.Bits())
}
