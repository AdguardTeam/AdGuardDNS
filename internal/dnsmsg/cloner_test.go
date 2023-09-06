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

// clonerTestCase is the type for the common test cases for the cloner tests and
// benchmarks.
type clonerTestCase struct {
	msg      *dns.Msg
	wantFull assert.BoolAssertionFunc
	name     string
}

// clonerTestCases are the common test cases for the clone benchmarks.
var clonerTestCases = []clonerTestCase{{
	msg:      dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET),
	name:     "req_a",
	wantFull: assert.True,
}, {
	msg: dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET),
		dnsservertest.SectionAnswer{
			dnsservertest.NewA(testFQDN, 10, testIPv4),
		},
	),
	name:     "resp_a",
	wantFull: assert.True,
}, {
	msg: dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET),
		dnsservertest.SectionAnswer{
			dnsservertest.NewA(testFQDN, 10, testIPv4),
			dnsservertest.NewA(testFQDN, 10, testIPv4.Next()),
		},
	),
	name:     "resp_a_many",
	wantFull: assert.True,
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
	name:     "resp_a_soa",
	wantFull: assert.True,
}, {
	msg:      dnsservertest.NewReq(testFQDN, dns.TypeAAAA, dns.ClassINET),
	name:     "req_aaaa",
	wantFull: assert.True,
}, {
	msg: dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeAAAA, dns.ClassINET),
		dnsservertest.SectionAnswer{
			dnsservertest.NewAAAA(testFQDN, 10, testIPv6),
		},
	),
	name:     "resp_aaaa",
	wantFull: assert.True,
}, {
	msg: dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET),
		dnsservertest.SectionAnswer{
			dnsservertest.NewCNAME(testFQDN, 10, "cname.example."),
			dnsservertest.NewA("cname.example.", 10, testIPv4),
		},
	),
	name:     "resp_cname_a",
	wantFull: assert.True,
}, {
	msg: dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq("4.3.2.1.in-addr.arpa", dns.TypePTR, dns.ClassINET),
		dnsservertest.SectionAnswer{
			dnsservertest.NewPTR("4.3.2.1.in-addr.arpa", 10, "ptr.example."),
		},
	),
	name:     "resp_ptr",
	wantFull: assert.True,
}, {
	msg: dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeTXT, dns.ClassINET),
		dnsservertest.SectionAnswer{
			dnsservertest.NewTXT(testFQDN, 10, "a", "b", "c"),
		},
	),
	name:     "resp_txt",
	wantFull: assert.True,
}, {
	msg: dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeSRV, dns.ClassINET),
		dnsservertest.SectionAnswer{
			dnsservertest.NewSRV(testFQDN, 10, "target.example.", 1, 1, 8080),
		},
	),
	name:     "resp_srv",
	wantFull: assert.True,
}, {
	msg: dnsservertest.NewResp(
		dns.RcodeSuccess,
		dnsservertest.NewReq(testFQDN, dns.TypeDNSKEY, dns.ClassINET),
		dnsservertest.SectionAnswer{
			&dns.DNSKEY{},
		},
	),
	name:     "resp_not_full",
	wantFull: assert.False,
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
		&dns.SVCBPort{Port: 443},
	}),
	name:     "resp_https",
	wantFull: assert.True,
}, {
	msg: newHTTPSResp([]dns.SVCBKeyValue{
		&dns.SVCBIPv4Hint{Hint: []net.IP{}},
		&dns.SVCBIPv6Hint{Hint: []net.IP{}},
	}),
	name:     "resp_https_empty_hint",
	wantFull: assert.True,
}}

// newHTTPSResp is a hepler that returns a response of type HTTPS with the given
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

func TestCloner_Clone(t *testing.T) {
	c := dnsmsg.NewCloner()

	for _, tc := range clonerTestCases {
		t.Run(tc.name, func(t *testing.T) {
			clone, full := c.Clone(tc.msg)
			assert.NotSame(t, tc.msg, clone)
			assert.Equal(t, tc.msg, clone)
			tc.wantFull(t, full)

			// Check again after putting it back.
			c.Put(clone)

			clone, full = c.Clone(tc.msg)
			assert.NotSame(t, tc.msg, clone)
			assert.Equal(t, tc.msg, clone)
			tc.wantFull(t, full)
		})
	}
}

// Sinks for benchmarks
var (
	msgSink  *dns.Msg
	boolSink bool
)

func BenchmarkClone(b *testing.B) {
	for _, tc := range clonerTestCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				msgSink = dnsmsg.Clone(tc.msg)
			}

			require.Equal(b, tc.msg, msgSink)
		})
	}

	// Most recent results, on a ThinkPad X13 with a Ryzen Pro 7 CPU:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/querylog
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkClone/req_a-16     	32849714	       231.7 ns/op	     168 B/op	       2 allocs/op
	//	BenchmarkClone/resp_a-16    	12051967	       509.1 ns/op	     256 B/op	       5 allocs/op
	//	BenchmarkClone/resp_a_many-16         	 8579755	       669.4 ns/op	     344 B/op	       7 allocs/op
	//	BenchmarkClone/resp_a_soa-16          	10393932	       681.9 ns/op	     368 B/op	       6 allocs/op
	//	BenchmarkClone/req_aaaa-16            	25616247	       232.1 ns/op	     168 B/op	       2 allocs/op
	//	BenchmarkClone/resp_aaaa-16           	14519920	       493.4 ns/op	     264 B/op	       5 allocs/op
	//	BenchmarkClone/resp_cname_a-16        	 8652282	       662.2 ns/op	     320 B/op	       6 allocs/op
	//	BenchmarkClone/resp_ptr-16            	13558555	       370.0 ns/op	     232 B/op	       4 allocs/op
	//	BenchmarkClone/resp_txt-16            	12322016	       532.7 ns/op	     296 B/op	       5 allocs/op
	//	BenchmarkClone/resp_srv-16            	15878784	       396.3 ns/op	     248 B/op	       4 allocs/op
	//	BenchmarkClone/resp_not_full-16       	15718658	       384.6 ns/op	     248 B/op	       4 allocs/op
	//	BenchmarkClone/resp_https-16          	 2621149	      2020 ns/op	     880 B/op	      24 allocs/op
	//	BenchmarkClone/resp_https_empty_hint-16         	 6829873	       890.8 ns/op	     424 B/op	       8 allocs/op
}

func BenchmarkCloner_Clone(b *testing.B) {
	c := dnsmsg.NewCloner()

	for _, tc := range clonerTestCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				msgSink, boolSink = c.Clone(tc.msg)
				if i < b.N-1 {
					// Don't put the last one to be sure that we can compare
					// that one.
					c.Put(msgSink)
				}
			}

			require.Equal(b, tc.msg, msgSink)
			tc.wantFull(b, boolSink)
		})
	}

	// Most recent results, on a ThinkPad X13 with a Ryzen Pro 7 CPU:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/querylog
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkCloner_Clone/req_a-16                  	163590546	        36.33 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkCloner_Clone/resp_a-16                 	100000000	        56.55 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkCloner_Clone/resp_a_many-16            	72498543	        84.52 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkCloner_Clone/resp_a_soa-16             	81750753	        73.07 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkCloner_Clone/req_aaaa-16               	165287482	        39.00 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkCloner_Clone/resp_aaaa-16              	99625165	        59.56 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkCloner_Clone/resp_cname_a-16           	72154432	        81.15 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkCloner_Clone/resp_ptr-16               	100418211	        60.88 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkCloner_Clone/resp_txt-16               	80963180	        73.66 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkCloner_Clone/resp_srv-16               	89021206	        69.35 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkCloner_Clone/resp_not_full-16          	31277523	       187.6 ns/op	      64 B/op	       1 allocs/op
	//	BenchmarkCloner_Clone/resp_https-16             	14601229	       396.3 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkCloner_Clone/resp_https_empty_hint-16  	45725181	       127.4 ns/op	       0 B/op	       0 allocs/op
}
