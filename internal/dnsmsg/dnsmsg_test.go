package dnsmsg_test

import (
	"fmt"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// Common filtered response TTL constants.
const (
	testFltRespTTL    = 10 * time.Second
	testFltRespTTLSec = uint32(testFltRespTTL / time.Second)
)

// Common domain names for tests.
const (
	testDomain = "test.example"
	testFQDN   = testDomain + "."
)

// Common test constants.
const (
	ipv4MaskBits = 24
	ipv4Scope    = ipv4MaskBits
	ipv6MaskBits = 64
	ipv6Scope    = ipv6MaskBits
)

// newECSExtraMsg is a helper constructor for ECS messages.
func newECSExtraMsg(ip netip.Addr, ecsFam netutil.AddrFamily, mask uint8) (msg *dns.Msg) {
	var scope uint8
	switch ecsFam {
	case netutil.AddrFamilyIPv4:
		scope = ipv4Scope
	case netutil.AddrFamilyIPv6:
		scope = ipv6Scope
	default:
		panic(fmt.Errorf("unsupported ecs addr fam %s", ecsFam))
	}

	msg = dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET)
	msg.SetEdns0(dnsmsg.DefaultEDNSUDPSize, true)
	msg.Extra = append(msg.Extra, dnsservertest.NewECSExtra(
		ip.AsSlice(),
		uint16(ecsFam),
		mask,
		scope,
	))

	return msg
}

func TestClone(t *testing.T) {
	testCases := []struct {
		msg  *dns.Msg
		name string
	}{{
		msg:  nil,
		name: "nil",
	}, {
		msg:  &dns.Msg{},
		name: "empty",
	}, {
		msg: &dns.Msg{
			Answer: []dns.RR{},
		},
		name: "empty_slice_ans",
	}, {
		msg:  dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET),
		name: "a",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			clone := dnsmsg.Clone(tc.msg)
			assert.Equal(t, tc.msg, clone)
		})
	}
}

func TestECSFromMsg(t *testing.T) {
	ipv4Net := netip.MustParsePrefix("1.2.3.0/24")
	ipv6Net := netip.MustParsePrefix("2001:0:0102:0304::/64")

	msgNoOpt := dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET)

	testCases := []struct {
		msg        *dns.Msg
		wantECS    netip.Prefix
		name       string
		wantErrMsg string
		wantScope  uint8
	}{{
		msg:        msgNoOpt,
		wantECS:    netip.Prefix{},
		name:       "no_opt",
		wantErrMsg: "",
		wantScope:  0,
	}, {
		msg:        dnsmsg.Clone(msgNoOpt).SetEdns0(dnsmsg.DefaultEDNSUDPSize, true),
		wantECS:    netip.Prefix{},
		name:       "no_ecs",
		wantErrMsg: "",
		wantScope:  0,
	}, {
		msg:        newECSExtraMsg(ipv4Net.Addr(), netutil.AddrFamilyIPv4, ipv4MaskBits),
		wantECS:    ipv4Net,
		name:       "ecs_ipv4",
		wantErrMsg: "",
		wantScope:  ipv4Scope,
	}, {
		msg:        newECSExtraMsg(ipv4Net.Addr(), netutil.AddrFamilyIPv4, 0),
		wantECS:    netip.Prefix{},
		name:       "ecs_ipv4_zero_mask_addr",
		wantErrMsg: "bad ecs: ip 1.2.3.0 has non-zero bits beyond prefix 0",
		wantScope:  0,
	}, {
		msg:        newECSExtraMsg(netip.IPv4Unspecified(), netutil.AddrFamilyIPv4, 0),
		wantECS:    netip.PrefixFrom(netip.IPv4Unspecified(), 0),
		name:       "ecs_ipv4_zero",
		wantErrMsg: "",
		wantScope:  ipv4Scope,
	}, {
		msg:        newECSExtraMsg(ipv4Net.Addr(), netutil.AddrFamilyIPv4, 1),
		wantECS:    netip.Prefix{},
		name:       "ecs_ipv4_bad_ones",
		wantErrMsg: "bad ecs: ip 1.2.3.0 has non-zero bits beyond prefix 1",
		wantScope:  0,
	}, {
		msg:        newECSExtraMsg(ipv4Net.Addr(), netutil.AddrFamilyIPv4, math.MaxUint8),
		wantECS:    netip.Prefix{},
		name:       "ecs_ipv4_bad_too_much",
		wantErrMsg: "bad ecs: bad src netmask 255 for addr family ipv4",
		wantScope:  0,
	}, {
		msg:        newECSExtraMsg(ipv6Net.Addr(), netutil.AddrFamilyIPv6, ipv6MaskBits),
		wantECS:    ipv6Net,
		name:       "ecs_ipv6",
		wantErrMsg: "",
		wantScope:  ipv6Scope,
	}, {
		msg:        newECSExtraMsg(ipv6Net.Addr(), netutil.AddrFamilyIPv6, 1),
		wantECS:    netip.Prefix{},
		name:       "ecs_ipv6_bad_ones",
		wantErrMsg: "bad ecs: ip 2001:0:102:304:: has non-zero bits beyond prefix 1",
		wantScope:  0,
	}, {
		msg:        newECSExtraMsg(ipv6Net.Addr(), netutil.AddrFamilyIPv6, math.MaxUint8),
		wantECS:    netip.Prefix{},
		name:       "ecs_ipv6_bad_too_much",
		wantErrMsg: "bad ecs: bad src netmask 255 for addr family ipv6",
		wantScope:  0,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ecs, scope, err := dnsmsg.ECSFromMsg(tc.msg)
			assert.Equal(t, tc.wantECS, ecs)
			assert.Equal(t, tc.wantScope, scope)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}
