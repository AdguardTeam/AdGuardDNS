package access_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func BenchmarkStandardBlocker_IsBlocked(b *testing.B) {
	blocker := access.NewStandardBlocker(&access.StandardBlockerConfig{
		BlocklistDomainRules: []string{
			"block.test",
		},
	})

	ctx := testutil.ContextWithTimeout(b, testTimeout)
	remoteAddr := netip.AddrPort{}

	b.Run("pass", func(b *testing.B) {
		req := dnsservertest.NewReq("pass.test", dns.TypeA, dns.ClassINET)

		var blocked bool

		b.ReportAllocs()
		for b.Loop() {
			blocked = blocker.IsBlocked(ctx, req, remoteAddr, nil)
		}

		assert.False(b, blocked)
	})

	b.Run("block", func(b *testing.B) {
		req := dnsservertest.NewReq("block.test", dns.TypeA, dns.ClassINET)

		var blocked bool

		b.ReportAllocs()
		for b.Loop() {
			blocked = blocker.IsBlocked(ctx, req, remoteAddr, nil)
		}

		assert.True(b, blocked)
	})

	// Most recent results:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/access
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkStandardBlocker_IsBlocked/pass-16         	 3009312	       378.2 ns/op	      16 B/op	       1 allocs/op
	//	BenchmarkStandardBlocker_IsBlocked/block-16        	 2518006	       421.9 ns/op	      24 B/op	       1 allocs/op
}
