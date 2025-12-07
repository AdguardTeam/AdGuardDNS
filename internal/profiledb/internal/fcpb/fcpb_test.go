package fcpb_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/fcpb"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/profiledbtest"
	"github.com/stretchr/testify/assert"
)

func TestCIDRRangesToPrefixes(t *testing.T) {
	invalidAddr := []byte{0, 1, 2, 3, 4}

	testCases := []struct {
		name         string
		wantPanicMsg string
		in           []*fcpb.CidrRange
		want         []netip.Prefix
	}{{
		name: "ipv4",
		in: []*fcpb.CidrRange{fcpb.CidrRange_builder{
			Address: profiledbtest.IPv4Bytes,
			Prefix:  24,
		}.Build()},
		want: []netip.Prefix{profiledbtest.IPv4Prefix},
	}, {
		name: "ipv6",
		in: []*fcpb.CidrRange{fcpb.CidrRange_builder{
			Address: profiledbtest.IPv6Bytes,
			Prefix:  32,
		}.Build()},
		want: []netip.Prefix{profiledbtest.IPv6Prefix},
	}, {
		name: "panic",
		in: []*fcpb.CidrRange{fcpb.CidrRange_builder{
			Address: invalidAddr,
		}.Build()},
		wantPanicMsg: fmt.Sprintf("bad address: %v", invalidAddr),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := func() {
				got := fcpb.CIDRRangesToPrefixes(tc.in)

				assert.Equal(t, tc.want, got)
			}

			if tc.wantPanicMsg != "" {
				assert.PanicsWithError(t, tc.wantPanicMsg, f)
			} else {
				assert.NotPanics(t, f)
			}
		})
	}
}
