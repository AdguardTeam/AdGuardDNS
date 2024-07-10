package dnsmsg_test

import (
	"net"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testClonerStat is a [dnsmsg.ClonerStat] implementation for tests.
type testClonerStat struct {
	// TODO(a.garipov): Consider better naming for methods of dnsmsg.ClonerStat.
	onOnClone func(isFull bool)
}

// type check
var _ dnsmsg.ClonerStat = (*testClonerStat)(nil)

// OnClone implements the [ClonerStat] interface for *testClonerStat.
func (s *testClonerStat) OnClone(isFull bool) {
	s.onOnClone(isFull)
}

// clonerTestCase is the type for the common test cases for the cloner tests and
// benchmarks.
type clonerTestCase struct {
	msg      *dns.Msg
	wantFull assert.BoolAssertionFunc
	name     string

	// handledByClone is true if [dnsmsg.Clone] is able to correctly clone the
	// message.  It is often false for the messages that contain nil slices,
	// because package github.com/miekg/dns often does not take nilness into
	// account.
	handledByClone bool
}

// clonerTestCases are the common test cases for the clone benchmarks.
var clonerTestCases = []clonerTestCase{{
	msg:            dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET),
	name:           "req_a",
	wantFull:       assert.True,
	handledByClone: true,
}, {
	msg: dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET),
		dnsservertest.SectionAnswer{
			dnsservertest.NewA(testFQDN, 10, testIPv4),
		},
	),
	name:           "resp_a",
	wantFull:       assert.True,
	handledByClone: true,
}, {
	msg: dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET),
		dnsservertest.SectionAnswer{
			dnsservertest.NewA(testFQDN, 10, testIPv4),
			dnsservertest.NewA(testFQDN, 10, testIPv4.Next()),
		},
	),
	name:           "resp_a_many",
	wantFull:       assert.True,
	handledByClone: true,
}, {
	msg: dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET),
		dnsservertest.SectionAnswer{
			dnsservertest.NewA(testFQDN, 10, testIPv4),
		},
		dnsservertest.SectionNs{
			dnsservertest.NewSOA(testFQDN, 10, "ns.example.", "mbox.example."),
		},
	),
	name:           "resp_a_soa",
	wantFull:       assert.True,
	handledByClone: true,
}, {
	msg:            dnsservertest.NewReq(testFQDN, dns.TypeAAAA, dns.ClassINET),
	name:           "req_aaaa",
	wantFull:       assert.True,
	handledByClone: true,
}, {
	msg: dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeAAAA, dns.ClassINET),
		dnsservertest.SectionAnswer{
			dnsservertest.NewAAAA(testFQDN, 10, testIPv6),
		},
	),
	name:           "resp_aaaa",
	wantFull:       assert.True,
	handledByClone: true,
}, {
	msg: dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET),
		dnsservertest.SectionAnswer{
			dnsservertest.NewCNAME(testFQDN, 10, "cname.example."),
			dnsservertest.NewA("cname.example.", 10, testIPv4),
		},
	),
	name:           "resp_cname_a",
	wantFull:       assert.True,
	handledByClone: true,
}, {
	msg:            newMXResp(testFQDN, 10),
	name:           "resp_mx",
	wantFull:       assert.True,
	handledByClone: true,
}, {
	msg: dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq("4.3.2.1.in-addr.arpa", dns.TypePTR, dns.ClassINET),
		dnsservertest.SectionAnswer{
			dnsservertest.NewPTR("4.3.2.1.in-addr.arpa", 10, "ptr.example."),
		},
	),
	name:           "resp_ptr",
	wantFull:       assert.True,
	handledByClone: true,
}, {
	msg: dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeTXT, dns.ClassINET),
		dnsservertest.SectionAnswer{
			dnsservertest.NewTXT(testFQDN, 10, "a", "b", "c"),
		},
	),
	name:           "resp_txt",
	wantFull:       assert.True,
	handledByClone: true,
}, {
	msg: dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeSRV, dns.ClassINET),
		dnsservertest.SectionAnswer{
			dnsservertest.NewSRV(testFQDN, 10, "target.example.", 1, 1, 8080),
		},
	),
	name:           "resp_srv",
	wantFull:       assert.True,
	handledByClone: true,
}, {
	msg: dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeDNSKEY, dns.ClassINET),
		dnsservertest.SectionAnswer{
			&dns.DNSKEY{},
		},
	),
	name:           "resp_not_full",
	wantFull:       assert.False,
	handledByClone: true,
}, {
	msg: newHTTPSResp([]dns.SVCBKeyValue{
		&dns.SVCBAlpn{Alpn: []string{"http/1.1", "h2", "h3"}},
		&dns.SVCBDoHPath{Template: "/dns-query"},
		&dns.SVCBECHConfig{ECH: []byte{0, 1, 2, 3}},
		&dns.SVCBIPv4Hint{Hint: []net.IP{
			testIPv4.AsSlice(),
			testIPv4.Next().AsSlice(),
		}},
		&dns.SVCBIPv6Hint{Hint: []net.IP{
			testIPv6.AsSlice(),
			testIPv6.Next().AsSlice(),
		}},
		&dns.SVCBLocal{KeyCode: dns.SVCBKey(1234), Data: []byte{3, 2, 1, 0}},
		&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ALPN}},
		&dns.SVCBNoDefaultAlpn{},
		&dns.SVCBOhttp{},
		&dns.SVCBPort{Port: 443},
	}),
	name:           "resp_https",
	wantFull:       assert.True,
	handledByClone: true,
}, {
	msg: newHTTPSResp([]dns.SVCBKeyValue{
		&dns.SVCBIPv4Hint{Hint: []net.IP{}},
		&dns.SVCBIPv6Hint{Hint: []net.IP{}},
	}),
	name:           "resp_https_empty_hint",
	wantFull:       assert.True,
	handledByClone: true,
}, {
	msg: newHTTPSResp([]dns.SVCBKeyValue{
		&dns.SVCBMandatory{},
	}),
	name:           "resp_https_empty_mandatory",
	wantFull:       assert.True,
	handledByClone: true,
}, {
	msg: newHTTPSResp([]dns.SVCBKeyValue{
		&dns.SVCBNoDefaultAlpn{},
		&dns.SVCBOhttp{},
	}),
	name:           "resp_https_empty_values",
	wantFull:       assert.True,
	handledByClone: true,
}, {
	msg:            newHTTPSResp(nil),
	name:           "resp_https_nil_hint",
	wantFull:       assert.True,
	handledByClone: false,
}, {
	msg: newOPTResp([]dns.EDNS0{
		&dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        1,
			SourceNetmask: 24,
			SourceScope:   24,
			Address:       net.IP{1, 2, 3, 0},
		},
	}),
	name:           "resp_a_ecs",
	wantFull:       assert.True,
	handledByClone: true,
}, {
	msg:            newOPTResp(nil),
	name:           "resp_a_ecs_nil",
	wantFull:       assert.True,
	handledByClone: false,
}}

// newHTTPSResp is a helper that returns a response of type HTTPS with the given
// parameter values.
func newHTTPSResp(kv []dns.SVCBKeyValue) (resp *dns.Msg) {
	ans := &dns.HTTPS{
		SVCB: dns.SVCB{
			Hdr: dns.RR_Header{
				Name:   testFQDN,
				Rrtype: dns.TypeHTTPS,
				Class:  dns.ClassINET,
				Ttl:    10,
			},
			Priority: 10,
			Target:   testFQDN,
			Value:    kv,
		},
	}

	return dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeHTTPS, dns.ClassINET),
		dnsservertest.SectionAnswer{ans},
	)
}

// newMXResp is a helper that returns a response of type MX with the given
// parameter values.
func newMXResp(mx string, pref uint16) (resp *dns.Msg) {
	ans := &dns.MX{
		Hdr: dns.RR_Header{
			Name:   testFQDN,
			Rrtype: dns.TypeMX,
			Class:  dns.ClassINET,
			Ttl:    10,
		},
		Preference: pref,
		Mx:         mx,
	}

	return dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeMX, dns.ClassINET),
		dnsservertest.SectionAnswer{ans},
	)
}

// newOPTResp is a helper that returns a response of type OPT with the given
// parameter values.
func newOPTResp(opt []dns.EDNS0) (resp *dns.Msg) {
	ex := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   testFQDN,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    10,
		},
		Option: opt,
	}

	return dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET),
		dnsservertest.SectionAnswer{
			dnsservertest.NewA(testFQDN, 10, testIPv4),
		},
		dnsservertest.SectionExtra{ex},
	)
}

func TestCloner_Clone(t *testing.T) {
	for _, tc := range clonerTestCases {
		t.Run(tc.name, func(t *testing.T) {
			var gotIsFull bool
			c := dnsmsg.NewCloner(&testClonerStat{
				onOnClone: func(isFull bool) {
					gotIsFull = isFull
				},
			})

			clone := c.Clone(tc.msg)
			assert.NotSame(t, tc.msg, clone)
			assert.Equal(t, tc.msg, clone)
			tc.wantFull(t, gotIsFull)

			// Check again after disposing of it.
			c.Dispose(clone)

			clone = c.Clone(tc.msg)
			assert.NotSame(t, tc.msg, clone)
			assert.Equal(t, tc.msg, clone)
			tc.wantFull(t, gotIsFull)
		})
	}
}

// Sinks for benchmarks
var (
	msgSink *dns.Msg
)

func BenchmarkClone(b *testing.B) {
	for _, tc := range clonerTestCases {
		b.Run(tc.name, func(b *testing.B) {
			if !tc.handledByClone {
				b.Skip("not handled by dnsmsg.Clone, skipping")
			}

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				msgSink = dnsmsg.Clone(tc.msg)
			}

			require.Equal(b, tc.msg, msgSink)
		})
	}

	// Most recent results, on a ThinkPad X13 with a Ryzen Pro 7 CPU:
	//
	//	goos: darwin
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg
	//	cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	//	BenchmarkClone/req_a-12							8987066		123.7 ns/op		168 B/op	2 allocs/op
	//	BenchmarkClone/resp_a-12						5619037		212.7 ns/op		256 B/op	5 allocs/op
	//	BenchmarkClone/resp_a_many-12					4385636		273.2 ns/op		344 B/op	7 allocs/op
	//	BenchmarkClone/resp_a_soa-12					4533913		263.1 ns/op		368 B/op	6 allocs/op
	//	BenchmarkClone/req_aaaa-12						10196326	116.9 ns/op		168 B/op	2 allocs/op
	//	BenchmarkClone/resp_aaaa-12						5666234		211.8 ns/op		264 B/op	5 allocs/op
	//	BenchmarkClone/resp_cname_a-12					4713193		255.4 ns/op		320 B/op	6 allocs/op
	//	BenchmarkClone/resp_mx-12						6539623		181.8 ns/op		248 B/op	4 allocs/op
	//	BenchmarkClone/resp_ptr-12						6744601		179.8 ns/op		232 B/op	4 allocs/op
	//	BenchmarkClone/resp_txt-12						5120538		230.8 ns/op		296 B/op	5 allocs/op
	//	BenchmarkClone/resp_srv-12						6549402		181.5 ns/op		248 B/op	4 allocs/op
	//	BenchmarkClone/resp_not_full-12					6529968		181.4 ns/op		248 B/op	4 allocs/op
	//	BenchmarkClone/resp_https-12					1361680		880.8 ns/op		896 B/op	24 allocs/op
	//	BenchmarkClone/resp_https_empty_hint-12			3548672		345.3 ns/op		424 B/op	8 allocs/op
	//	BenchmarkClone/resp_https_empty_mandatory-12	4055365		291.6 ns/op		384 B/op	7 allocs/op
	//	BenchmarkClone/resp_https_empty_values-12		4434608		269.8 ns/op		376 B/op	6 allocs/op
	//	BenchmarkClone/resp_a_ecs-12					3741008		318.5 ns/op		384 B/op	8 allocs/op
}

func BenchmarkCloner_Clone(b *testing.B) {
	for _, tc := range clonerTestCases {
		b.Run(tc.name, func(b *testing.B) {
			var gotIsFull bool
			c := dnsmsg.NewCloner(&testClonerStat{
				onOnClone: func(isFull bool) {
					gotIsFull = isFull
				},
			})

			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				msgSink = c.Clone(tc.msg)
				if i < b.N-1 {
					// Don't dispose of the last one to be sure that we can
					// compare that one.
					c.Dispose(msgSink)
				}
			}

			require.Equal(b, tc.msg, msgSink)
			tc.wantFull(b, gotIsFull)
		})
	}

	// Most recent results, on a ThinkPad X13 with a Ryzen Pro 7 CPU:
	//
	//	goos: darwin
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg
	//	cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	//	BenchmarkCloner_Clone/req_a-12							28363105	39.40 ns/op		0 B/op		0 allocs/op
	//	BenchmarkCloner_Clone/resp_a-12							17288836	72.96 ns/op		0 B/op		0 allocs/op
	//	BenchmarkCloner_Clone/resp_a_many-12					11043524	105.9 ns/op		0 B/op		0 allocs/op
	//	BenchmarkCloner_Clone/resp_a_soa-12						14058405	84.21 ns/op		0 B/op		0 allocs/op
	//	BenchmarkCloner_Clone/req_aaaa-12						31732440	37.61 ns/op		0 B/op		0 allocs/op
	//	BenchmarkCloner_Clone/resp_aaaa-12						19054647	65.48 ns/op		0 B/op		0 allocs/op
	//	BenchmarkCloner_Clone/resp_cname_a-12					13343605	90.35 ns/op		0 B/op		0 allocs/op
	//	BenchmarkCloner_Clone/resp_mx-12						19749904	59.09 ns/op		0 B/op		0 allocs/op
	//	BenchmarkCloner_Clone/resp_ptr-12						20109849	60.00 ns/op		0 B/op		0 allocs/op
	//	BenchmarkCloner_Clone/resp_txt-12						17270551	64.07 ns/op		0 B/op		0 allocs/op
	//	BenchmarkCloner_Clone/resp_srv-12						18197905	66.67 ns/op		0 B/op		0 allocs/op
	//	BenchmarkCloner_Clone/resp_not_full-12					12713991	95.55 ns/op		64 B/op		1 allocs/op
	//	BenchmarkCloner_Clone/resp_https-12						3037629		395.9 ns/op		0 B/op		0 allocs/op
	//	BenchmarkCloner_Clone/resp_https_empty_hint-12			10258635	119.3 ns/op		0 B/op		0 allocs/op
	//	BenchmarkCloner_Clone/resp_https_empty_mandatory-12		14306239	82.14 ns/op		0 B/op		0 allocs/op
	//	BenchmarkCloner_Clone/resp_https_empty_values-12		15568735	80.12 ns/op		0 B/op		0 allocs/op
	//	BenchmarkCloner_Clone/resp_https_nil_hint-12			20536422	59.70 ns/op		0 B/op		0 allocs/op
	//	BenchmarkCloner_Clone/resp_a_ecs-12						10978351	107.8 ns/op		0 B/op		0 allocs/op
	//	BenchmarkCloner_Clone/resp_a_ecs_nil-12					13626586	93.56 ns/op		0 B/op		0 allocs/op
}

func FuzzCloner_Clone(f *testing.F) {
	for _, tc := range clonerTestCases {
		b, err := tc.msg.Pack()
		require.NoError(f, err)

		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		msg := &dns.Msg{}
		err := msg.Unpack(input)
		if err != nil || len(msg.Question) != 1 {
			return
		}

		var gotIsFull bool
		c := dnsmsg.NewCloner(&testClonerStat{
			onOnClone: func(isFull bool) {
				gotIsFull = isFull
			},
		})

		clone := c.Clone(msg)
		if !gotIsFull {
			// TODO(a.garipov): Currently we cannot analyze partial clones,
			// because these may contain e.g. HTTPS records in Ns fields, which
			// [dns.Copy] doesn't clone properly due to nilness issues.
			// Consider changing the code to fix that.
			return
		}

		assert.Equal(t, msg, clone)

		c.Dispose(clone)
		clone = c.Clone(msg)

		require.True(t, gotIsFull)

		assert.Equal(t, msg, clone)
	})
}
