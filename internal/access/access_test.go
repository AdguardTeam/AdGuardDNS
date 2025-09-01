package access_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is the common timeout for tests.
const testTimeout = 1 * time.Second

// testAccessMtrc is the common profile access engine metrics for tests.
var testAccessMtrc = access.EmptyProfileMetrics{}

// testCases is the list of test cases for the [IsBlocked] function.
var testCases = []struct {
	want assert.BoolAssertionFunc
	name string
	host string
	qt   uint16
}{{
	want: assert.False,
	name: "pass",
	host: "pass.test",
	qt:   dns.TypeA,
}, {
	want: assert.True,
	name: "blocked_domain_a",
	host: "block.test",
	qt:   dns.TypeA,
}, {
	want: assert.True,
	name: "blocked_domain_https",
	host: "block.test",
	qt:   dns.TypeHTTPS,
}, {
	want: assert.True,
	name: "uppercase_domain",
	host: "uppercase.test",
	qt:   dns.TypeHTTPS,
}, {
	want: assert.False,
	name: "pass_qt",
	host: "block_aaaa.test",
	qt:   dns.TypeA,
}, {
	want: assert.True,
	name: "block_qt",
	host: "block_aaaa.test",
	qt:   dns.TypeAAAA,
}, {
	want: assert.True,
	name: "allowlist_block",
	host: "block.allowlist.test",
	qt:   dns.TypeA,
}, {
	want: assert.False,
	name: "allowlist_test",
	host: "allow.allowlist.test",
	qt:   dns.TypeA,
}}

// newTestGlobal is a test helper that returns a new [access.Global] with test
// rules.
func newTestGlobal(t testing.TB) (global *access.Global) {
	t.Helper()

	global, err := access.NewGlobal([]string{
		"block.test",
		"UPPERCASE.test",
		"||block_aaaa.test^$dnstype=AAAA",
		"||allowlist.test^",
		"@@||allow.allowlist.test^",
	}, nil)
	require.NoError(t, err)

	return global
}

func TestGlobal_IsBlockedHost(t *testing.T) {
	t.Parallel()

	global := newTestGlobal(t)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			blocked := global.IsBlockedHost(tc.host, tc.qt)
			tc.want(t, blocked)
		})
	}
}

func TestGlobal_IsBlockedIP(t *testing.T) {
	t.Parallel()

	global, err := access.NewGlobal([]string{}, []netip.Prefix{
		netip.MustParsePrefix("192.0.2.1/32"),
		netip.MustParsePrefix("198.51.100.0/24"),
	})
	require.NoError(t, err)

	testCases := []struct {
		want assert.BoolAssertionFunc
		ip   netip.Addr
		name string
	}{{
		want: assert.False,
		name: "pass",
		ip:   netip.MustParseAddr("192.0.2.0"),
	}, {
		want: assert.True,
		name: "block_ip",
		ip:   netip.MustParseAddr("192.0.2.1"),
	}, {
		want: assert.False,
		name: "pass_subnet",
		ip:   netip.MustParseAddr("198.51.101.1"),
	}, {
		want: assert.True,
		name: "block_subnet",
		ip:   netip.MustParseAddr("198.51.100.1"),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			blocked := global.IsBlockedIP(tc.ip)
			tc.want(t, blocked)
		})
	}
}

func BenchmarkGlobal_IsBlockedHost(b *testing.B) {
	global := newTestGlobal(b)

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			var blocked bool

			b.ReportAllocs()
			for b.Loop() {
				blocked = global.IsBlockedHost(tc.host, tc.qt)
			}

			tc.want(b, blocked)
		})
	}

	// Most recent results:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/access
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	// BenchmarkGlobal_IsBlockedHost/pass-16         	 2313513	       515.0 ns/op	      16 B/op	       1 allocs/op
	// BenchmarkGlobal_IsBlockedHost/blocked_domain_a-16         	 1604049	       683.4 ns/op	      24 B/op	       1 allocs/op
	// BenchmarkGlobal_IsBlockedHost/blocked_domain_https-16     	 1981204	       597.7 ns/op	      24 B/op	       1 allocs/op
	// BenchmarkGlobal_IsBlockedHost/uppercase_domain-16         	 2093197	       590.5 ns/op	      24 B/op	       1 allocs/op
	// BenchmarkGlobal_IsBlockedHost/pass_qt-16                  	 1961065	       653.3 ns/op	      24 B/op	       1 allocs/op
	// BenchmarkGlobal_IsBlockedHost/block_qt-16                 	  768783	      1567 ns/op	      24 B/op	       1 allocs/op
	// BenchmarkGlobal_IsBlockedHost/allowlist_block-16          	  759159	      1890 ns/op	      32 B/op	       1 allocs/op
	// BenchmarkGlobal_IsBlockedHost/allowlist_test-16           	  371722	      3170 ns/op	      32 B/op	       1 allocs/op
}

func BenchmarkGlobal_IsBlockedIP(b *testing.B) {
	global, err := access.NewGlobal([]string{}, []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
	})
	require.NoError(b, err)

	b.Run("pass", func(b *testing.B) {
		ip := netip.MustParseAddr("192.0.3.0")

		var blocked bool

		b.ReportAllocs()
		for b.Loop() {
			blocked = global.IsBlockedIP(ip)
		}

		assert.False(b, blocked)
	})

	b.Run("block", func(b *testing.B) {
		ip := netip.MustParseAddr("192.0.2.0")

		var blocked bool

		b.ReportAllocs()
		for b.Loop() {
			blocked = global.IsBlockedIP(ip)
		}

		assert.True(b, blocked)
	})

	// Most recent results:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/access
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkGlobal_IsBlockedIP/pass-16         	100000000	        10.18 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkGlobal_IsBlockedIP/block-16        	141876058	         8.545 ns/op	       0 B/op	       0 allocs/op
}
