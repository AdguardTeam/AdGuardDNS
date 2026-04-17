package filecacheopb

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/fcpb"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/profiledbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestBlockingModesToInternal(t *testing.T) {
	testCases := []struct {
		wantMode dnsmsg.BlockingMode
		profile  *fcpb.Profile
		name     string
	}{{
		name: "custom_ips",
		wantMode: &dnsmsg.BlockingModeCustomIP{
			IPv4: []netip.Addr{profiledbtest.IPv4},
			IPv6: []netip.Addr{profiledbtest.IPv6},
		},
		profile: fcpb.Profile_builder{
			BlockingModeCustomIp: fcpb.BlockingModeCustomIP_builder{
				Ipv4: [][]byte{profiledbtest.IPv4Bytes},
				Ipv6: [][]byte{profiledbtest.IPv6Bytes},
			}.Build(),
			AdultBlockingModeCustomIp: fcpb.BlockingModeCustomIP_builder{
				Ipv4: [][]byte{profiledbtest.IPv4Bytes},
				Ipv6: [][]byte{profiledbtest.IPv6Bytes},
			}.Build(),
			SafeBrowsingBlockingModeCustomIp: fcpb.BlockingModeCustomIP_builder{
				Ipv4: [][]byte{profiledbtest.IPv4Bytes},
				Ipv6: [][]byte{profiledbtest.IPv6Bytes},
			}.Build(),
		}.Build(),
	}, {
		name:     "nxdomain",
		wantMode: &dnsmsg.BlockingModeNXDOMAIN{},
		profile: fcpb.Profile_builder{
			BlockingModeNxdomain:             &fcpb.BlockingModeNXDOMAIN{},
			AdultBlockingModeNxdomain:        &fcpb.BlockingModeNXDOMAIN{},
			SafeBrowsingBlockingModeNxdomain: &fcpb.BlockingModeNXDOMAIN{},
		}.Build(),
	}, {
		name:     "null_ip",
		wantMode: &dnsmsg.BlockingModeNullIP{},
		profile: fcpb.Profile_builder{
			BlockingModeNullIp:             &fcpb.BlockingModeNullIP{},
			AdultBlockingModeNullIp:        &fcpb.BlockingModeNullIP{},
			SafeBrowsingBlockingModeNullIp: &fcpb.BlockingModeNullIP{},
		}.Build(),
	}, {
		name:     "refused",
		wantMode: &dnsmsg.BlockingModeREFUSED{},
		profile: fcpb.Profile_builder{
			BlockingModeRefused:             &fcpb.BlockingModeREFUSED{},
			AdultBlockingModeRefused:        &fcpb.BlockingModeREFUSED{},
			SafeBrowsingBlockingModeRefused: &fcpb.BlockingModeREFUSED{},
		}.Build(),
	}, {
		name:     "null_blocking_mode",
		wantMode: nil,
		profile:  fcpb.Profile_builder{}.Build(),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bmAdult, err := adultBlockingModeToInternal(tc.profile)
			require.NoError(t, err)
			assert.Equal(t, tc.wantMode, bmAdult)

			bm, err := blockingModeToInternal(tc.profile)
			require.NoError(t, err)
			assert.Equal(t, tc.wantMode, bm)

			bmSafeBrowsing, err := safeBrowsingBlockingModeToInternal(tc.profile)
			require.NoError(t, err)
			assert.Equal(t, tc.wantMode, bmSafeBrowsing)
		})
	}
}

func TestSetBlockingModes(t *testing.T) {
	testCases := []struct {
		mode         dnsmsg.BlockingMode
		wantProfile  *fcpb.Profile
		name         string
		wantPanicMsg string
	}{{
		name: "custom_ips",
		mode: &dnsmsg.BlockingModeCustomIP{
			IPv4: []netip.Addr{profiledbtest.IPv4},
			IPv6: []netip.Addr{profiledbtest.IPv6},
		},
		wantProfile: fcpb.Profile_builder{
			BlockingModeCustomIp: fcpb.BlockingModeCustomIP_builder{
				Ipv4: [][]byte{profiledbtest.IPv4Bytes},
				Ipv6: [][]byte{profiledbtest.IPv6Bytes},
			}.Build(),
			AdultBlockingModeCustomIp: fcpb.BlockingModeCustomIP_builder{
				Ipv4: [][]byte{profiledbtest.IPv4Bytes},
				Ipv6: [][]byte{profiledbtest.IPv6Bytes},
			}.Build(),
			SafeBrowsingBlockingModeCustomIp: fcpb.BlockingModeCustomIP_builder{
				Ipv4: [][]byte{profiledbtest.IPv4Bytes},
				Ipv6: [][]byte{profiledbtest.IPv6Bytes},
			}.Build(),
		}.Build(),
	}, {
		name: "nxdomain",
		mode: &dnsmsg.BlockingModeNXDOMAIN{},
		wantProfile: fcpb.Profile_builder{
			BlockingModeNxdomain:             &fcpb.BlockingModeNXDOMAIN{},
			AdultBlockingModeNxdomain:        &fcpb.BlockingModeNXDOMAIN{},
			SafeBrowsingBlockingModeNxdomain: &fcpb.BlockingModeNXDOMAIN{},
		}.Build(),
	}, {
		name: "null_ip",
		mode: &dnsmsg.BlockingModeNullIP{},
		wantProfile: fcpb.Profile_builder{
			BlockingModeNullIp:             &fcpb.BlockingModeNullIP{},
			AdultBlockingModeNullIp:        &fcpb.BlockingModeNullIP{},
			SafeBrowsingBlockingModeNullIp: &fcpb.BlockingModeNullIP{},
		}.Build(),
	}, {
		name: "refused",
		mode: &dnsmsg.BlockingModeREFUSED{},
		wantProfile: fcpb.Profile_builder{
			BlockingModeRefused:             &fcpb.BlockingModeREFUSED{},
			AdultBlockingModeRefused:        &fcpb.BlockingModeREFUSED{},
			SafeBrowsingBlockingModeRefused: &fcpb.BlockingModeREFUSED{},
		}.Build(),
	}, {
		name:         "null_blocking_mode",
		mode:         nil,
		wantProfile:  fcpb.Profile_builder{}.Build(),
		wantPanicMsg: "bad blocking mode <nil>(<nil>)",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := func() {
				builder := &fcpb.Profile_builder{}

				setBlockingMode(builder, tc.mode)
				setAdultBlockingMode(builder, tc.mode)
				setSafeBrowsingBlockingMode(builder, tc.mode)

				got := builder.Build()
				assert.True(t, proto.Equal(tc.wantProfile, got))
			}

			if tc.wantPanicMsg == "" {
				assert.NotPanics(t, f)
			} else {
				assert.PanicsWithError(t, tc.wantPanicMsg, f)
			}
		})
	}
}
