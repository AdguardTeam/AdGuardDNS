package agdtest

import (
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
)

var (
	// IPv4 is a common IPv4 address for tests.  It is intended to be used in
	// bind config tests.
	IPv4 = netip.MustParseAddr("192.0.2.1")

	// IPv6 is a common IPv6 address for tests.  It is intended to be used in
	// bind config tests.
	IPv6 = netip.MustParseAddr("2001:db8::")

	// PrefixV4 is a common IPv4 prefix address for tests.  It is intended to be
	// used in bind config tests.  [IPv4] is included in this subnet prefix.
	PrefixV4 = netip.MustParsePrefix("192.0.2.0/24")

	// SinglePrefixV4 is a single prefix for [IPv4].  It is intended to be used
	// in bind config tests.
	SinglePrefixV4 = netip.PrefixFrom(IPv4, IPv4.BitLen())

	// BindConfigV4 is a common test server bind configuration for [IPv4]
	// address and port 53.
	BindConfigV4 = &agdnet.BindConfig{
		Addr: agdnet.BindConfigAddrDefault(netip.AddrPortFrom(IPv4, 53)),
	}

	// BindConfigV6 is a common test server bind configuration for [IPv6]
	// address and port 53.
	BindConfigV6 = &agdnet.BindConfig{
		Addr: agdnet.BindConfigAddrDefault(netip.AddrPortFrom(IPv6, 53)),
	}

	// BindConfigIfaceV4 is a common test server bind configuration with
	// [ListenConfig] and [PrefixV4] address.
	BindConfigIfaceV4 = &agdnet.BindConfig{
		ListenConfig: &ListenConfig{},
		Addr: &agdnet.BindConfigAddrPrefix{
			Prefix: PrefixV4,
			Net:    "",
			Port:   53,
		},
	}

	// BindConfigIfaceV4SingleIP is a common test server bind configuration with
	// [ListenConfig] and [SinglePrefixV4] address.
	BindConfigIfaceV4SingleIP = &agdnet.BindConfig{
		ListenConfig: &ListenConfig{},
		Addr: &agdnet.BindConfigAddrPrefix{
			Prefix: SinglePrefixV4,
			Net:    "",
			Port:   53,
		},
	}
)
