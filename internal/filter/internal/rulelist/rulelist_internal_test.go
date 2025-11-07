package rulelist

import (
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

	// cacheCount is the common count of cache items for filtering tests.
	cacheCount = 1
)

// testRemoteIP is the client IP for tests
var testRemoteIP = netip.MustParseAddr("1.2.3.4")

// testFltListID is the common filter list IDs for tests.
const testFltListID filter.ID = "fl1"

// testBlockRule is the common blocking rule for tests.
const testBlockRule = "||" + testHostBlocked + "\n"

func BenchmarkBaseFilter_SetURLFilterResult(b *testing.B) {
	const qt = dns.TypeA

	ctx := b.Context()

	benchCases := []struct {
		request *urlfilter.DNSRequest
		cache   ResultCache
		want    require.BoolAssertionFunc
		name    string
	}{{
		name:  "blocked",
		cache: EmptyResultCache{},
		request: &urlfilter.DNSRequest{
			ClientIP: testRemoteIP,
			Hostname: testHostBlocked,
			DNSType:  qt,
		},
		want: require.True,
	}, {
		name:  "other",
		cache: EmptyResultCache{},
		request: &urlfilter.DNSRequest{
			ClientIP: testRemoteIP,
			Hostname: testHostOther,
			DNSType:  qt,
		},
		want: require.False,
	}, {
		name:  "blocked_with_cache",
		cache: NewResultCache(cacheCount, true),
		request: &urlfilter.DNSRequest{
			ClientIP: testRemoteIP,
			Hostname: testHostBlocked,
			DNSType:  qt,
		},
		want: require.True,
	}, {
		name:  "other_with_cache",
		cache: NewResultCache(cacheCount, true),
		request: &urlfilter.DNSRequest{
			ClientIP: testRemoteIP,
			Hostname: testHostOther,
			DNSType:  qt,
		},
		want: require.False,
	}}

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			f := newBaseFilter([]byte(testBlockRule), testFltListID, "", bc.cache)
			res := &urlfilter.DNSResult{}

			// Warmup to fill the slices.
			ok := f.SetURLFilterResult(ctx, bc.request, res)
			bc.want(b, ok)

			b.ReportAllocs()
			for b.Loop() {
				res.Reset()
				ok = f.SetURLFilterResult(ctx, bc.request, res)
			}

			bc.want(b, ok)
		})
	}

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist
	//	cpu: Apple M3
	//	BenchmarkBaseFilter_SetURLFilterResult/blocked-8         	             1793678	        670.9 ns/op	      24 B/op	       1 allocs/op
	//	BenchmarkBaseFilter_SetURLFilterResult/other-8           	             5599238	        222.0 ns/op	      24 B/op	       1 allocs/op
	//	BenchmarkBaseFilter_SetURLFilterResult/blocked_with_cache-8         	38971425	        31.01 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkBaseFilter_SetURLFilterResult/other_with_cache-8           	57606105	        21.05 ns/op	       0 B/op	       0 allocs/op
}
