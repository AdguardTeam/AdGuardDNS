package dnsmsg_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConstructor_NewAnswerHTTPS_andSVCB(t *testing.T) {
	// Preconditions.

	mc := dnsmsg.NewConstructor(nil, &dnsmsg.BlockingModeNullIP{}, testFltRespTTL)
	req := &dns.Msg{
		Question: []dns.Question{{
			Name: "abcd",
		}},
	}

	// Constants and helper values.

	const prio = 32

	// Helper functions.

	dnssvcb := func(key, value string) (svcb *rules.DNSSVCB) {
		svcb = &rules.DNSSVCB{
			Target:   testFQDN,
			Priority: prio,
		}

		if key == "" {
			return svcb
		}

		svcb.Params = map[string]string{
			key: value,
		}

		return svcb
	}

	wantsvcb := func(kv dns.SVCBKeyValue) (want *dns.SVCB) {
		want = &dns.SVCB{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeSVCB,
				Ttl:    testFltRespTTLSec,
				Class:  dns.ClassINET,
			},
			Priority: prio,
			Target:   testFQDN,
		}

		if kv != nil {
			want.Value = []dns.SVCBKeyValue{kv}
		}

		return want
	}

	// Tests.

	testCases := []struct {
		svcb *rules.DNSSVCB
		want *dns.SVCB
		name string
	}{{
		svcb: dnssvcb("", ""),
		want: wantsvcb(nil),
		name: "no_params",
	}, {
		svcb: dnssvcb("foo", "bar"),
		want: wantsvcb(nil),
		name: "invalid",
	}, {
		svcb: dnssvcb("alpn", http3.NextProtoH3),
		want: wantsvcb(&dns.SVCBAlpn{Alpn: []string{http3.NextProtoH3}}),
		name: "alpn",
	}, {
		svcb: dnssvcb("dohpath", "/some/url/path"),
		want: wantsvcb(&dns.SVCBDoHPath{Template: "/some/url/path"}),
		name: "dohpath",
	}, {
		svcb: dnssvcb("ech", "AAAA"),
		want: wantsvcb(&dns.SVCBECHConfig{ECH: []byte{0, 0, 0}}),
		name: "ech",
	}, {
		svcb: dnssvcb("ech", "%BAD%"),
		want: wantsvcb(nil),
		name: "ech_invalid",
	}, {
		svcb: dnssvcb("ipv4hint", testIPv4.String()),
		want: wantsvcb(&dns.SVCBIPv4Hint{Hint: []net.IP{net.IP(testIPv4.AsSlice()).To16()}}),
		name: "ipv4hint",
	}, {
		svcb: dnssvcb("ipv4hint", "1.2.3.04"),
		want: wantsvcb(nil),
		name: "ipv4hint_invalid",
	}, {
		svcb: dnssvcb("ipv6hint", testIPv6.String()),
		want: wantsvcb(&dns.SVCBIPv6Hint{Hint: []net.IP{testIPv6.AsSlice()}}),
		name: "ipv6hint",
	}, {
		svcb: dnssvcb("ipv6hint", ":::1"),
		want: wantsvcb(nil),
		name: "ipv6hint_invalid",
	}, {
		svcb: dnssvcb("mandatory", "alpn"),
		want: wantsvcb(&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ALPN}}),
		name: "mandatory",
	}, {
		svcb: dnssvcb("mandatory", "invalid"),
		want: wantsvcb(nil),
		name: "mandatory_invalid",
	}, {
		svcb: dnssvcb("no-default-alpn", ""),
		want: wantsvcb(&dns.SVCBNoDefaultAlpn{}),
		name: "no_default_alpn",
	}, {
		svcb: dnssvcb("port", "8080"),
		want: wantsvcb(&dns.SVCBPort{Port: 8080}),
		name: "port",
	}, {
		svcb: dnssvcb("port", "1005008080"),
		want: wantsvcb(nil),
		name: "bad_port",
	}}

	for _, tc := range testCases {
		t.Run(tc.name+"_https", func(t *testing.T) {
			want := &dns.HTTPS{SVCB: *tc.want}
			want.Hdr.Rrtype = dns.TypeHTTPS

			got := mc.NewAnswerHTTPS(req, tc.svcb)
			assert.Equal(t, want, got)
		})

		t.Run(tc.name+"_svcb", func(t *testing.T) {
			got := mc.NewAnswerSVCB(req, tc.svcb)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestConstructor_NewDDR(t *testing.T) {
	const (
		port       uint16 = 12345
		prio       uint16 = 123
		target            = "test.target"
		targetFQDN        = target + "."
		dohPath           = "/dns-query"
	)

	mc := dnsmsg.NewConstructor(nil, &dnsmsg.BlockingModeNullIP{}, testFltRespTTL)

	testCases := []struct {
		name     string
		ipv4s    []netip.Addr
		ipv6s    []netip.Addr
		wantVals []dns.SVCBKeyValue
		proto    dnsserver.Protocol
	}{{
		name:  "dot",
		ipv4s: nil,
		ipv6s: nil,
		wantVals: []dns.SVCBKeyValue{
			&dns.SVCBAlpn{Alpn: dnsserver.ProtoDoT.ALPN()},
			&dns.SVCBPort{Port: port},
		},
		proto: dnsserver.ProtoDoT,
	}, {
		name:  "doq",
		ipv4s: nil,
		ipv6s: nil,
		wantVals: []dns.SVCBKeyValue{
			&dns.SVCBAlpn{Alpn: dnsserver.ProtoDoQ.ALPN()},
			&dns.SVCBPort{Port: port},
		},
		proto: dnsserver.ProtoDoQ,
	}, {
		name:  "doh",
		ipv4s: nil,
		ipv6s: nil,
		wantVals: []dns.SVCBKeyValue{
			&dns.SVCBAlpn{Alpn: dnsserver.ProtoDoH.ALPN()},
			&dns.SVCBPort{Port: port},
			&dns.SVCBDoHPath{Template: dohPath},
		},
		proto: dnsserver.ProtoDoH,
	}, {
		name:  "dot_ipv4_only",
		ipv4s: []netip.Addr{testIPv4},
		ipv6s: nil,
		wantVals: []dns.SVCBKeyValue{
			&dns.SVCBAlpn{Alpn: dnsserver.ProtoDoT.ALPN()},
			&dns.SVCBPort{Port: port},
			&dns.SVCBIPv4Hint{Hint: []net.IP{testIPv4.AsSlice()}},
		},
		proto: dnsserver.ProtoDoT,
	}, {
		name:  "dot_ipv6_only",
		ipv4s: nil,
		ipv6s: []netip.Addr{testIPv6},
		wantVals: []dns.SVCBKeyValue{
			&dns.SVCBAlpn{Alpn: dnsserver.ProtoDoT.ALPN()},
			&dns.SVCBPort{Port: port},
			&dns.SVCBIPv6Hint{Hint: []net.IP{testIPv6.AsSlice()}},
		},
		proto: dnsserver.ProtoDoT,
	}, {
		name:  "dot_ipv4_ipv6",
		ipv4s: []netip.Addr{testIPv4},
		ipv6s: []netip.Addr{testIPv6},
		wantVals: []dns.SVCBKeyValue{
			&dns.SVCBAlpn{Alpn: dnsserver.ProtoDoT.ALPN()},
			&dns.SVCBPort{Port: port},
			&dns.SVCBIPv4Hint{Hint: []net.IP{testIPv4.AsSlice()}},
			&dns.SVCBIPv6Hint{Hint: []net.IP{testIPv6.AsSlice()}},
		},
		proto: dnsserver.ProtoDoT,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			svcb := mc.NewDDRTemplate(tc.proto, target, dohPath, tc.ipv4s, tc.ipv6s, port, prio)
			require.NotNil(t, svcb)

			assert.Equal(t, targetFQDN, svcb.Target)
			assert.Equal(t, prio, svcb.Priority)
			assert.Equal(t, testFltRespTTLSec, svcb.Hdr.Ttl)
			assert.ElementsMatch(t, tc.wantVals, svcb.Value)
		})
	}

	for _, unsupProto := range []dnsserver.Protocol{
		dnsserver.ProtoDNS,
		dnsserver.ProtoDNSCrypt,
	} {
		t.Run(unsupProto.String(), func(t *testing.T) {
			assert.Panics(t, func() {
				_ = mc.NewDDRTemplate(unsupProto, target, "", nil, nil, port, prio)
			})
		})
	}
}
