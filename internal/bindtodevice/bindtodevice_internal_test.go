package bindtodevice

import (
	"net"
	"net/netip"
	"time"
)

// Common timeout for tests
const testTimeout = 1 * time.Second

// Common addresses for tests.
var (
	testLAddr = &net.UDPAddr{
		IP:   net.IP{1, 2, 3, 4},
		Port: 53,
	}
	testRAddr = &net.UDPAddr{
		IP:   net.IP{5, 6, 7, 8},
		Port: 1234,
	}
)

// Common subnets for tests.
var (
	testSubnetIPv4 = netip.MustParsePrefix("1.2.3.0/24")
	testSubnetIPv6 = netip.MustParsePrefix("1234:5678::/64")
)
