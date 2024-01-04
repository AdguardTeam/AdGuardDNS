package agdnet_test

import "net/netip"

// Common subnets for tests.
var (
	testSubnetIPv4 = netip.MustParsePrefix("1.2.3.0/24")
	testSubnetIPv6 = netip.MustParsePrefix("1234:5678::/64")
)
