package agdnet_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCachingResolver_Resolve(t *testing.T) {
	const testHost = "addr.example"

	var numLookups uint64
	wantIPv4 := []netip.Addr{netip.MustParseAddr("1.2.3.4")}
	wantIPv6 := []netip.Addr{netip.MustParseAddr("1234::5678")}
	r := &agdtest.Resolver{
		OnLookupNetIP: func(
			ctx context.Context,
			fam netutil.AddrFamily,
			host string,
		) (ips []netip.Addr, err error) {
			numLookups++

			if fam == netutil.AddrFamilyIPv4 {
				return wantIPv4, nil
			}

			return nil, nil
		},
	}

	cached := agdnet.NewCachingResolver(r, 1*timeutil.Day)

	testCases := []struct {
		name    string
		host    string
		wantIPs []netip.Addr
		wantNum uint64
		fam     netutil.AddrFamily
	}{{
		name:    "initial",
		host:    testHost,
		wantIPs: wantIPv4,
		wantNum: 1,
		fam:     netutil.AddrFamilyIPv4,
	}, {
		name:    "cached",
		host:    testHost,
		wantIPs: wantIPv4,
		wantNum: 1,
		fam:     netutil.AddrFamilyIPv4,
	}, {
		name:    "other_network",
		host:    testHost,
		wantIPs: nil,
		wantNum: 2,
		fam:     netutil.AddrFamilyIPv6,
	}, {
		name:    "ipv4",
		host:    wantIPv4[0].String(),
		wantIPs: wantIPv4,
		wantNum: 2,
		fam:     netutil.AddrFamilyIPv4,
	}, {
		name:    "ipv6",
		host:    wantIPv6[0].String(),
		wantIPs: wantIPv6,
		wantNum: 2,
		fam:     netutil.AddrFamilyIPv6,
	}}

	ctx := context.Background()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cached.LookupNetIP(ctx, tc.fam, tc.host)
			require.NoError(t, err)

			assert.Equal(t, tc.wantNum, numLookups)
			assert.Equal(t, tc.wantIPs, got)
		})
	}
}
