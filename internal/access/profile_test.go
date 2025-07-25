package access_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestDefaultProfile_Config(t *testing.T) {
	conf := &access.ProfileConfig{
		AllowedNets:          []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")},
		BlockedNets:          []netip.Prefix{netip.MustParsePrefix("2.2.2.0/24")},
		AllowedASN:           []geoip.ASN{1},
		BlockedASN:           []geoip.ASN{1, 2},
		BlocklistDomainRules: []string{"block.test"},
	}

	cons := access.NewProfileConstructor(testAccessMtrc)
	a := cons.New(conf)
	got := a.Config()
	assert.Equal(t, conf.AllowedNets, got.AllowedNets)
	assert.Equal(t, conf.BlockedNets, got.BlockedNets)
	assert.Equal(t, conf.AllowedASN, got.AllowedASN)
	assert.Equal(t, conf.BlockedASN, got.BlockedASN)
	assert.Equal(t, conf.BlocklistDomainRules, got.BlocklistDomainRules)
}

func TestDefaultProfile_IsBlocked(t *testing.T) {
	passAddrPort := netip.MustParseAddrPort("3.3.3.3:3333")

	conf := &access.ProfileConfig{
		AllowedNets: []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")},
		BlockedNets: []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")},
		AllowedASN:  []geoip.ASN{1},
		BlockedASN:  []geoip.ASN{1, 2},
		BlocklistDomainRules: []string{
			"block.test",
			"UPPERCASE.test",
			"||block_aaaa.test^$dnstype=AAAA",
			"||allowlist.test^",
			"@@||allow.allowlist.test^",
		},
	}

	cons := access.NewProfileConstructor(testAccessMtrc)
	a := cons.New(conf)

	testCases := []struct {
		loc   *geoip.Location
		want  assert.BoolAssertionFunc
		rAddr netip.AddrPort
		name  string
		host  string
		qt    uint16
	}{{
		want:  assert.False,
		name:  "pass",
		host:  "pass.test",
		qt:    dns.TypeA,
		rAddr: passAddrPort,
		loc:   nil,
	}, {
		want:  assert.True,
		name:  "blocked_domain_A",
		host:  "block.test",
		qt:    dns.TypeA,
		rAddr: passAddrPort,
		loc:   nil,
	}, {
		want:  assert.True,
		name:  "blocked_domain_HTTPS",
		host:  "block.test",
		qt:    dns.TypeHTTPS,
		rAddr: passAddrPort,
		loc:   nil,
	}, {
		want:  assert.True,
		name:  "uppercase_domain",
		host:  "uppercase.test",
		qt:    dns.TypeHTTPS,
		rAddr: passAddrPort,
		loc:   nil,
	}, {
		want:  assert.False,
		name:  "pass_qt",
		host:  "block_aaaa.test",
		qt:    dns.TypeA,
		rAddr: passAddrPort,
		loc:   nil,
	}, {
		want:  assert.True,
		name:  "block_qt",
		host:  "block_aaaa.test",
		qt:    dns.TypeAAAA,
		rAddr: passAddrPort,
		loc:   nil,
	}, {
		want:  assert.True,
		name:  "allowlist_block",
		host:  "block.allowlist.test",
		qt:    dns.TypeA,
		rAddr: passAddrPort,
		loc:   nil,
	}, {
		want:  assert.False,
		name:  "allowlist_test",
		host:  "allow.allowlist.test",
		qt:    dns.TypeA,
		rAddr: passAddrPort,
		loc:   nil,
	}, {
		want:  assert.False,
		name:  "pass_ip",
		rAddr: netip.MustParseAddrPort("1.1.1.1:57"),
		host:  "pass.test",
		qt:    dns.TypeA,
		loc:   nil,
	}, {
		want:  assert.True,
		name:  "block_subnet",
		rAddr: netip.MustParseAddrPort("1.1.1.2:57"),
		host:  "pass.test",
		qt:    dns.TypeA,
		loc:   nil,
	}, {
		want:  assert.False,
		name:  "pass_subnet",
		rAddr: netip.MustParseAddrPort("1.2.2.2:57"),
		host:  "pass.test",
		qt:    dns.TypeA,
		loc:   nil,
	}, {
		want:  assert.True,
		name:  "block_host_pass_asn",
		rAddr: passAddrPort,
		host:  "block.test",
		qt:    dns.TypeA,
		loc:   &geoip.Location{ASN: 1},
	}, {
		want:  assert.False,
		name:  "pass_asn",
		rAddr: passAddrPort,
		host:  "pass.test",
		qt:    dns.TypeA,
		loc:   &geoip.Location{ASN: 1},
	}, {
		want:  assert.True,
		name:  "block_asn",
		rAddr: passAddrPort,
		host:  "pass.test",
		qt:    dns.TypeA,
		loc:   &geoip.Location{ASN: 2},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := dnsservertest.NewReq(tc.host, tc.qt, dns.ClassINET)

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			blocked := a.IsBlocked(ctx, req, tc.rAddr, tc.loc)
			tc.want(t, blocked)
		})
	}
}

func TestDefaultProfile_IsBlocked_prefixAllowlist(t *testing.T) {
	conf := &access.ProfileConfig{
		AllowedNets: []netip.Prefix{
			netip.MustParsePrefix("2.2.2.0/24"),
			netip.MustParsePrefix("3.3.0.0/16"),
		},
		BlockedNets:          []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		AllowedASN:           nil,
		BlockedASN:           nil,
		BlocklistDomainRules: nil,
	}

	cons := access.NewProfileConstructor(testAccessMtrc)
	a := cons.New(conf)

	testCases := []struct {
		want  assert.BoolAssertionFunc
		rAddr netip.AddrPort
		name  string
	}{{
		want:  assert.True,
		name:  "block_before",
		rAddr: netip.MustParseAddrPort("1.1.1.1:2222"),
	}, {
		want:  assert.False,
		name:  "allow_first",
		rAddr: netip.MustParseAddrPort("2.2.2.1:2222"),
	}, {
		want:  assert.False,
		name:  "allow_second",
		rAddr: netip.MustParseAddrPort("3.3.1.1:2222"),
	}, {
		want:  assert.True,
		name:  "block_second",
		rAddr: netip.MustParseAddrPort("3.4.1.1:2222"),
	}, {
		want:  assert.True,
		name:  "block_after",
		rAddr: netip.MustParseAddrPort("4.4.1.1:2222"),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := dnsservertest.NewReq("pass.test", dns.TypeA, dns.ClassINET)

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			blocked := a.IsBlocked(ctx, req, tc.rAddr, nil)
			tc.want(t, blocked)
		})
	}
}

func BenchmarkDefaultProfile_IsBlocked(b *testing.B) {
	passAddrPort := netip.MustParseAddrPort("3.3.3.3:3333")

	conf := &access.ProfileConfig{
		AllowedNets: []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")},
		BlockedNets: []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")},
		AllowedASN:  []geoip.ASN{1},
		BlockedASN:  []geoip.ASN{1, 2},
		BlocklistDomainRules: []string{
			"block.test",
			"UPPERCASE.test",
			"||block_aaaa.test^$dnstype=AAAA",
			"||allowlist.test^",
			"@@||allow.allowlist.test^",
		},
	}

	cons := access.NewProfileConstructor(testAccessMtrc)
	a := cons.New(conf)

	ctx := testutil.ContextWithTimeout(b, testTimeout)

	benchCases := []struct {
		want assert.BoolAssertionFunc
		req  *dns.Msg
		name string
	}{{
		want: assert.False,
		req:  dnsservertest.NewReq("pass.test", dns.TypeA, dns.ClassINET),
		name: "pass",
	}, {
		want: assert.True,
		req:  dnsservertest.NewReq("block.test", dns.TypeA, dns.ClassINET),
		name: "block",
	}}

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			var blocked bool
			for b.Loop() {
				blocked = a.IsBlocked(ctx, bc.req, passAddrPort, nil)
			}

			bc.want(b, blocked)
		})
	}

	// Most recent results:
	//
	// goos: darwin
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/access
	// cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	// BenchmarkDefaultProfile_IsBlocked/pass-12         	 2761741	       421.9 ns/op	      96 B/op	       2 allocs/op
	// BenchmarkDefaultProfile_IsBlocked/block-12        	 2143516	       556.1 ns/op	     128 B/op	       4 allocs/op
}
