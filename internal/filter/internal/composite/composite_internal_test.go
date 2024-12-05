package composite

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Sinks for benchmarks.
var (
	resultSink internal.Result
)

func BenchmarkFilter_FilterReqWithRuleLists(b *testing.B) {
	blockingRL, err := rulelist.NewFromString(
		filtertest.RuleBlockStr+"\n",
		"test",
		"",
		rulelist.ResultCacheEmpty{},
	)
	require.NoError(b, err)

	f := New(&Config{
		RuleLists: []*rulelist.Refreshable{blockingRL},
	})

	req := filtertest.NewRequest(b, "", filtertest.HostBlocked, filtertest.IPv4Client, dns.TypeA)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		resultSink = f.filterReqWithRuleLists(req)
	}

	// Most recent results:
	//
	//	goos: darwin
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/composite
	//	cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	//	BenchmarkFilter_FilterReqWithRuleLists-12	1023186		1144 ns/op	186 B/op	7 allocs/op
}
