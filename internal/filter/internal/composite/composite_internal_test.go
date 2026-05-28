package composite

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func BenchmarkFilter_FilterReqWithRuleLists(b *testing.B) {
	blockingRL := rulelist.NewFromString(
		filtertest.RuleBlockStr+"\n",
		"test",
		"",
		rulelist.EmptyResultCache{},
	)

	f := New(&Config{
		RuleLists: []*rulelist.Refreshable{blockingRL},
	})

	ctx := context.Background()
	req := filtertest.NewRequest(b, "", filtertest.HostBlocked, filtertest.IPv4Client, dns.TypeA)

	// Warmup to fill the pools.
	res, _ := f.filterReqWithRuleLists(ctx, req)

	b.ReportAllocs()
	for b.Loop() {
		res, _ = f.filterReqWithRuleLists(ctx, req)
	}

	require.NotNil(b, res)

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/composite
	//	cpu: Apple M4 Pro
	//	BenchmarkFilter_FilterReqWithRuleLists-14    	 2594946	       460.5 ns/op	     105 B/op	       3 allocs/op
}
