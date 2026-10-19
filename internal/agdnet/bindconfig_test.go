package agdnet_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/stretchr/testify/assert"
)

func TestBindConfigs_HasAddr(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		bindConfig *agdnet.BindConfig
		want       assert.BoolAssertionFunc
		name       string
	}{{
		bindConfig: agdtest.BindConfigV4,
		want:       assert.True,
		name:       "addr_has",
	}, {
		bindConfig: agdtest.BindConfigV6,
		want:       assert.False,
		name:       "addr_missing",
	}, {
		bindConfig: agdtest.BindConfigIfaceV4SingleIP,
		want:       assert.True,
		name:       "prefix_has",
	}, {
		bindConfig: agdtest.BindConfigIfaceV4,
		want:       assert.False,
		name:       "prefix_missing",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			bc := agdnet.BindConfigs{tc.bindConfig}
			tc.want(t, bc.HasAddr(netip.AddrPortFrom(agdtest.IPv4, 53)))
		})
	}
}

func TestBindConfigs_HasIPv6(t *testing.T) {
	t.Parallel()

	bc := agdnet.BindConfigs{}
	assert.False(t, bc.HasIPv6())

	bc = agdnet.BindConfigs{agdtest.BindConfigIfaceV4}
	assert.False(t, bc.HasIPv6())

	bc = agdnet.BindConfigs{agdtest.BindConfigV6}
	assert.True(t, bc.HasIPv6())
}

func TestBindConfigs_Prefixes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		bindData *agdnet.BindConfig
		name     string
		want     []netip.Prefix
	}{{
		bindData: agdtest.BindConfigV4,
		want:     []netip.Prefix{netip.PrefixFrom(agdtest.IPv4, agdtest.IPv4.BitLen())},
		name:     "addr_port_v4",
	}, {
		bindData: agdtest.BindConfigV6,
		want:     []netip.Prefix{netip.PrefixFrom(agdtest.IPv6, agdtest.IPv6.BitLen())},
		name:     "addr_port_v6",
	}, {
		bindData: agdtest.BindConfigIfaceV4,
		want:     []netip.Prefix{agdtest.PrefixV4},
		name:     "prefix",
	}, {
		bindData: agdtest.BindConfigIfaceV4SingleIP,
		want:     []netip.Prefix{agdtest.SinglePrefixV4},
		name:     "prefix_single_ip",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			bc := agdnet.BindConfigs{tc.bindData}

			assert.Equal(t, tc.want, bc.Prefixes())
		})
	}
}
