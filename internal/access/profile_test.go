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
	t.Parallel()

	conf := &access.ProfileConfig{
		AllowedNets:          []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
		BlockedNets:          []netip.Prefix{netip.MustParsePrefix("192.0.2.2/32")},
		AllowedASN:           []geoip.ASN{1},
		BlockedASN:           []geoip.ASN{1, 2},
		BlocklistDomainRules: []string{"block.test"},
		StandardEnabled:      true,
	}

	cons := access.NewProfileConstructor(&access.ProfileConstructorConfig{
		Metrics:  testAccessMtrc,
		Standard: access.EmptyBlocker{},
	})

	a := cons.New(conf)
	got := a.Config()
	assert.Equal(t, conf, got)
}

func TestDefaultProfile_IsBlocked(t *testing.T) {
	t.Parallel()

	passAddrPort := netip.MustParseAddrPort("192.0.2.3:3333")

	std := access.NewStandardBlocker(&access.StandardBlockerConfig{
		AllowedNets: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32")},
		BlockedNets: []netip.Prefix{netip.MustParsePrefix("192.0.2.20/32")},
		AllowedASN:  []geoip.ASN{10},
		BlockedASN:  []geoip.ASN{10, 20},
		BlocklistDomainRules: []string{
			"block.std.test",
			"UPPERCASE.STD.test",
			"||block_aaaa.std.test^$dnstype=AAAA",
			"||allowlist.std.test^",
			"@@||allow.allowlist.std.test^",
		},
	})

	conf := &access.ProfileConfig{
		AllowedNets: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
		BlockedNets: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/32")},
		AllowedASN:  []geoip.ASN{1},
		BlockedASN:  []geoip.ASN{1, 2},
		BlocklistDomainRules: []string{
			"block.test",
			"UPPERCASE.test",
			"||block_aaaa.test^$dnstype=AAAA",
			"||allowlist.test^",
			"@@||allow.allowlist.test^",
		},
		StandardEnabled: true,
	}

	cons := access.NewProfileConstructor(&access.ProfileConstructorConfig{
		Metrics:  testAccessMtrc,
		Standard: std,
	})
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
		rAddr: netip.MustParseAddrPort("192.0.2.1:57"),
		host:  "pass.test",
		qt:    dns.TypeA,
		loc:   nil,
	}, {
		want:  assert.True,
		name:  "block_subnet",
		rAddr: netip.MustParseAddrPort("192.0.2.2:57"),
		host:  "pass.test",
		qt:    dns.TypeA,
		loc:   nil,
	}, {
		want:  assert.False,
		name:  "pass_subnet",
		rAddr: netip.MustParseAddrPort("192.0.2.1:57"),
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
	}, {
		want:  assert.True,
		name:  "standard_blocked_domain_A",
		host:  "block.std.test",
		qt:    dns.TypeA,
		rAddr: passAddrPort,
		loc:   nil,
	}, {
		want:  assert.True,
		name:  "standard_blocked_domain_HTTPS",
		host:  "block.std.test",
		qt:    dns.TypeHTTPS,
		rAddr: passAddrPort,
		loc:   nil,
	}, {
		want:  assert.True,
		name:  "standard_uppercase_domain",
		host:  "uppercase.std.test",
		qt:    dns.TypeHTTPS,
		rAddr: passAddrPort,
		loc:   nil,
	}, {
		want:  assert.False,
		name:  "standard_pass_qt",
		host:  "block_aaaa.std.test",
		qt:    dns.TypeA,
		rAddr: passAddrPort,
		loc:   nil,
	}, {
		want:  assert.True,
		name:  "standard_block_qt",
		host:  "block_aaaa.std.test",
		qt:    dns.TypeAAAA,
		rAddr: passAddrPort,
		loc:   nil,
	}, {
		want:  assert.True,
		name:  "standard_allowlist_block",
		host:  "block.allowlist.std.test",
		qt:    dns.TypeA,
		rAddr: passAddrPort,
		loc:   nil,
	}, {
		want:  assert.False,
		name:  "standard_allowlist_test",
		host:  "allow.allowlist.std.test",
		qt:    dns.TypeA,
		rAddr: passAddrPort,
		loc:   nil,
	}, {
		want:  assert.False,
		name:  "standard_pass_ip",
		rAddr: netip.MustParseAddrPort("192.0.2.21:57"),
		host:  "pass.std.test",
		qt:    dns.TypeA,
		loc:   nil,
	}, {
		want:  assert.True,
		name:  "standard_block_subnet",
		rAddr: netip.MustParseAddrPort("192.0.2.20:57"),
		host:  "pass.std.test",
		qt:    dns.TypeA,
		loc:   nil,
	}, {
		want:  assert.False,
		name:  "standard_pass_subnet",
		rAddr: netip.MustParseAddrPort("192.0.2.11:57"),
		host:  "pass.std.test",
		qt:    dns.TypeA,
		loc:   nil,
	}, {
		want:  assert.True,
		name:  "standard_block_host_pass_asn",
		rAddr: passAddrPort,
		host:  "block.std.test",
		qt:    dns.TypeA,
		loc:   &geoip.Location{ASN: 10},
	}, {
		want:  assert.False,
		name:  "standard_pass_asn",
		rAddr: passAddrPort,
		host:  "pass.std.test",
		qt:    dns.TypeA,
		loc:   &geoip.Location{ASN: 10},
	}, {
		want:  assert.True,
		name:  "standard_block_asn",
		rAddr: passAddrPort,
		host:  "pass.std.test",
		qt:    dns.TypeA,
		loc:   &geoip.Location{ASN: 20},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := dnsservertest.NewReq(tc.host, tc.qt, dns.ClassINET)

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			blocked := a.IsBlocked(ctx, req, tc.rAddr, tc.loc)
			tc.want(t, blocked)
		})
	}
}

func TestDefaultProfile_IsBlocked_prefixAllowlist(t *testing.T) {
	t.Parallel()

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

	cons := access.NewProfileConstructor(&access.ProfileConstructorConfig{
		Metrics:  testAccessMtrc,
		Standard: access.EmptyBlocker{},
	})
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
			t.Parallel()

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

	cons := access.NewProfileConstructor(&access.ProfileConstructorConfig{
		Metrics:  testAccessMtrc,
		Standard: access.EmptyBlocker{},
	})
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
			// Warmup to fill the pools and the slices.
			blocked := a.IsBlocked(ctx, bc.req, passAddrPort, nil)
			bc.want(b, blocked)

			b.ReportAllocs()
			for b.Loop() {
				blocked = a.IsBlocked(ctx, bc.req, passAddrPort, nil)
			}

			bc.want(b, blocked)
		})
	}

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/access
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDefaultProfile_IsBlocked/pass-16         	 2638284	       452.4 ns/op	      16 B/op	       1 allocs/op
	//	BenchmarkDefaultProfile_IsBlocked/block-16        	 2224564	       539.1 ns/op	      24 B/op	       1 allocs/op
}
