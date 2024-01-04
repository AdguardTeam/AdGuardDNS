package agdnet_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/stretchr/testify/assert"
)

func TestPrefixAddr(t *testing.T) {
	const (
		port    = 56789
		network = "tcp"
	)

	fullPrefix := netip.MustParsePrefix("1.2.3.4/32")

	testCases := []struct {
		in   *agdnet.PrefixNetAddr
		want string
		name string
	}{{
		in: &agdnet.PrefixNetAddr{
			Prefix: testSubnetIPv4,
			Net:    network,
			Port:   port,
		},
		want: fmt.Sprintf(
			"%s/%d",
			netip.AddrPortFrom(testSubnetIPv4.Addr(), port), testSubnetIPv4.Bits(),
		),
		name: "ipv4",
	}, {
		in: &agdnet.PrefixNetAddr{
			Prefix: testSubnetIPv6,
			Net:    network,
			Port:   port,
		},
		want: fmt.Sprintf(
			"%s/%d",
			netip.AddrPortFrom(testSubnetIPv6.Addr(), port), testSubnetIPv6.Bits(),
		),
		name: "ipv6",
	}, {
		in: &agdnet.PrefixNetAddr{
			Prefix: fullPrefix,
			Net:    network,
			Port:   port,
		},
		want: netip.AddrPortFrom(fullPrefix.Addr(), port).String(),
		name: "ipv4_full",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.in.String())
			assert.Equal(t, network, tc.in.Network())
		})
	}
}
