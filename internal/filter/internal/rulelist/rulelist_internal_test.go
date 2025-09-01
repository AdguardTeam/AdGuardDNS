package rulelist

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/urlfilter"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// TODO(d.kolyshev):  Use constants from filtertest package.
const (
	// testHostBlocked is the blocked request host for tests.
	testHostBlocked = "blocked.example"

	// testHostOther is the other request host for tests.
	testHostOther = "other.example"
)

// testRemoteIP is the client IP for tests
var testRemoteIP = netip.MustParseAddr("1.2.3.4")

// testFltListID is the common filter list IDs for tests.
const testFltListID filter.ID = "fl1"

// testBlockRule is the common blocking rule for tests.
const testBlockRule = "||" + testHostBlocked + "\n"

// TODO(a.garipov):  Add benchmarks with a cache.
func BenchmarkBaseFilter_SetURLFilterResult(b *testing.B) {
	f := newBaseFilter(
		[]byte(testBlockRule),
		testFltListID,
		"",
		EmptyResultCache{},
	)

	const qt = dns.TypeA

	ctx := context.Background()
	res := &urlfilter.DNSResult{}

	b.Run("blocked", func(b *testing.B) {
		req := &urlfilter.DNSRequest{
			ClientIP: testRemoteIP,
			Hostname: testHostBlocked,
			DNSType:  qt,
		}

		var ok bool
		b.ReportAllocs()
		for b.Loop() {
			res.Reset()
			ok = f.SetURLFilterResult(ctx, req, res)
		}

		require.True(b, ok)
	})

	b.Run("other", func(b *testing.B) {
		req := &urlfilter.DNSRequest{
			ClientIP: testRemoteIP,
			Hostname: testHostOther,
			DNSType:  qt,
		}

		var ok bool
		b.ReportAllocs()
		for b.Loop() {
			res.Reset()
			ok = f.SetURLFilterResult(ctx, req, res)
		}

		require.False(b, ok)
	})

	// Most recent results:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkBaseFilter_SetURLFilterResult/blocked-16         	  906486	      1372 ns/op	      24 B/op	       1 allocs/op
	//	BenchmarkBaseFilter_SetURLFilterResult/other-16           	 2203561	       609.1 ns/op	      24 B/op	       1 allocs/op
}
