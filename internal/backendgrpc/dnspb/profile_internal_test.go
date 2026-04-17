package dnspb

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

var (
	// testInvalidIPv4 is an invalid IPv4 address used for tests.
	testInvalidIPv4 = []byte("1.1.ab")

	// testInvalidIPv6 is an invalid IPv6 address used for tests.
	testInvalidIPv6 = []byte("1234abc:12d4:43")
)

func Test_safeBrowsingBlockingModeToInternal(t *testing.T) {
	t.Parallel()

	ipv4 := netutil.IPv4Localhost()
	ipv6 := netutil.IPv6Localhost()

	testCases := []struct {
		pbm        isDNSProfile_SafeBrowsingBlockingMode
		want       dnsmsg.BlockingMode
		name       string
		wantErrMsg string
	}{{
		name: "blocking_mode_custom_ip",
		pbm: &DNSProfile_SafeBrowsingBlockingModeCustomIp{
			SafeBrowsingBlockingModeCustomIp: &BlockingModeCustomIP{
				Ipv4: ipv4.AsSlice(),
				Ipv6: ipv6.AsSlice(),
			},
		},
		want: &dnsmsg.BlockingModeCustomIP{
			IPv4: []netip.Addr{ipv4},
			IPv6: []netip.Addr{ipv6},
		},
		wantErrMsg: "",
	}, {
		name: "blocking_mode_custom_ip_invalid_ipv4",
		pbm: &DNSProfile_SafeBrowsingBlockingModeCustomIp{
			SafeBrowsingBlockingModeCustomIp: &BlockingModeCustomIP{
				Ipv4: testInvalidIPv4,
			},
		},
		want:       nil,
		wantErrMsg: "bad custom ipv4: unexpected slice size",
	}, {
		name: "blocking_mode_custom_ip_invalid_ipv6",
		pbm: &DNSProfile_SafeBrowsingBlockingModeCustomIp{
			SafeBrowsingBlockingModeCustomIp: &BlockingModeCustomIP{
				Ipv4: ipv4.AsSlice(),
				Ipv6: testInvalidIPv6,
			},
		},
		want:       nil,
		wantErrMsg: "bad custom ipv6: unexpected slice size",
	}, {
		name: "blocking_mode_custom_ip_no_valid_ips",
		pbm: &DNSProfile_SafeBrowsingBlockingModeCustomIp{
			SafeBrowsingBlockingModeCustomIp: &BlockingModeCustomIP{},
		},
		want:       nil,
		wantErrMsg: "no valid custom ips found",
	}, {
		name:       "blocking_mode_nx_domain",
		pbm:        &DNSProfile_SafeBrowsingBlockingModeNxdomain{},
		want:       &dnsmsg.BlockingModeNXDOMAIN{},
		wantErrMsg: "",
	}, {
		name:       "blockind_mode_null_ip",
		pbm:        &DNSProfile_SafeBrowsingBlockingModeNullIp{},
		want:       &dnsmsg.BlockingModeNullIP{},
		wantErrMsg: "",
	}, {
		name:       "blocking_mode_refused",
		pbm:        &DNSProfile_SafeBrowsingBlockingModeRefused{},
		want:       &dnsmsg.BlockingModeREFUSED{},
		wantErrMsg: "",
	}, {
		name:       "nil_pbm",
		pbm:        nil,
		want:       nil,
		wantErrMsg: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := safeBrowsingBlockingModeToInternal(tc.pbm)
			assert.Equal(t, tc.want, got)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func Test_adultBlockingModeToInternal(t *testing.T) {
	t.Parallel()

	ipv4 := netutil.IPv4Localhost()
	ipv6 := netutil.IPv6Localhost()

	testCases := []struct {
		pbm        isDNSProfile_AdultBlockingMode
		want       dnsmsg.BlockingMode
		name       string
		wantErrMsg string
	}{{
		name: "blocking_mode_custom_ip",
		pbm: &DNSProfile_AdultBlockingModeCustomIp{
			AdultBlockingModeCustomIp: &BlockingModeCustomIP{
				Ipv4: ipv4.AsSlice(),
				Ipv6: ipv6.AsSlice(),
			},
		},
		want: &dnsmsg.BlockingModeCustomIP{
			IPv4: []netip.Addr{ipv4},
			IPv6: []netip.Addr{ipv6},
		},
		wantErrMsg: "",
	}, {
		name: "blocking_mode_custom_ip_invalid_ipv4",
		pbm: &DNSProfile_AdultBlockingModeCustomIp{
			AdultBlockingModeCustomIp: &BlockingModeCustomIP{
				Ipv4: testInvalidIPv4,
			},
		},
		want:       nil,
		wantErrMsg: "bad custom ipv4: unexpected slice size",
	}, {
		name: "blocking_mode_custom_ip_invalid_ipv6",
		pbm: &DNSProfile_AdultBlockingModeCustomIp{
			AdultBlockingModeCustomIp: &BlockingModeCustomIP{
				Ipv4: ipv4.AsSlice(),
				Ipv6: testInvalidIPv6,
			},
		},
		want:       nil,
		wantErrMsg: "bad custom ipv6: unexpected slice size",
	}, {
		name: "blocking_mode_custom_ip_no_valid_ips",
		pbm: &DNSProfile_AdultBlockingModeCustomIp{
			AdultBlockingModeCustomIp: &BlockingModeCustomIP{},
		},
		want:       nil,
		wantErrMsg: "no valid custom ips found",
	}, {
		name:       "blocking_mode_nx_domain",
		pbm:        &DNSProfile_AdultBlockingModeNxdomain{},
		want:       &dnsmsg.BlockingModeNXDOMAIN{},
		wantErrMsg: "",
	}, {
		name:       "blockind_mode_null_ip",
		pbm:        &DNSProfile_AdultBlockingModeNullIp{},
		want:       &dnsmsg.BlockingModeNullIP{},
		wantErrMsg: "",
	}, {
		name:       "blocking_mode_refused",
		pbm:        &DNSProfile_AdultBlockingModeRefused{},
		want:       &dnsmsg.BlockingModeREFUSED{},
		wantErrMsg: "",
	}, {
		name:       "nil_pbm",
		pbm:        nil,
		want:       nil,
		wantErrMsg: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := adultBlockingModeToInternal(tc.pbm)
			assert.Equal(t, tc.want, got)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func Test_blockingModeToInternal(t *testing.T) {
	t.Parallel()

	ipv4 := netutil.IPv4Localhost()
	ipv6 := netutil.IPv6Localhost()

	testCases := []struct {
		pbm        isDNSProfile_BlockingMode
		want       dnsmsg.BlockingMode
		name       string
		wantErrMsg string
	}{{
		name: "blocking_mode_custom_ip",
		pbm: &DNSProfile_BlockingModeCustomIp{
			BlockingModeCustomIp: &BlockingModeCustomIP{
				Ipv4: ipv4.AsSlice(),
				Ipv6: ipv6.AsSlice(),
			},
		},
		want: &dnsmsg.BlockingModeCustomIP{
			IPv4: []netip.Addr{ipv4},
			IPv6: []netip.Addr{ipv6},
		},
		wantErrMsg: "",
	}, {
		name: "blocking_mode_custom_ip_invalid_ipv4",
		pbm: &DNSProfile_BlockingModeCustomIp{
			BlockingModeCustomIp: &BlockingModeCustomIP{
				Ipv4: testInvalidIPv4,
			},
		},
		want:       nil,
		wantErrMsg: "bad custom ipv4: unexpected slice size",
	}, {
		name: "blocking_mode_custom_ip_invalid_ipv6",
		pbm: &DNSProfile_BlockingModeCustomIp{
			BlockingModeCustomIp: &BlockingModeCustomIP{
				Ipv4: ipv4.AsSlice(),
				Ipv6: testInvalidIPv6,
			},
		},
		want:       nil,
		wantErrMsg: "bad custom ipv6: unexpected slice size",
	}, {
		name: "blocking_mode_custom_ip_no_valid_ips",
		pbm: &DNSProfile_BlockingModeCustomIp{
			BlockingModeCustomIp: &BlockingModeCustomIP{},
		},
		want:       nil,
		wantErrMsg: "no valid custom ips found",
	}, {
		name:       "blocking_mode_nx_domain",
		pbm:        &DNSProfile_BlockingModeNxdomain{},
		want:       &dnsmsg.BlockingModeNXDOMAIN{},
		wantErrMsg: "",
	}, {
		name:       "blockind_mode_null_ip",
		pbm:        &DNSProfile_BlockingModeNullIp{},
		want:       &dnsmsg.BlockingModeNullIP{},
		wantErrMsg: "",
	}, {
		name:       "blocking_mode_refused",
		pbm:        &DNSProfile_BlockingModeRefused{},
		want:       &dnsmsg.BlockingModeREFUSED{},
		wantErrMsg: "",
	}, {
		name:       "nil_pbm",
		pbm:        nil,
		want:       &dnsmsg.BlockingModeNullIP{},
		wantErrMsg: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := blockingModeToInternal(tc.pbm)
			assert.Equal(t, tc.want, got)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}
