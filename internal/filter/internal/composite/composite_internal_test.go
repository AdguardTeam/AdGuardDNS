package composite

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
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

	var result filter.Result

	b.ReportAllocs()
	for b.Loop() {
		result = f.filterReqWithRuleLists(ctx, req)
	}

	assert.NotNil(b, result)

	// Most recent results:
	//
	// goos: darwin
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/composite
	// cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	// BenchmarkFilter_FilterReqWithRuleLists-12    	  760046	      1336 ns/op	     592 B/op	      12 allocs/op
}
