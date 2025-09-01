package composite

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/urlfilter"
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
		URLFilterRequest: &urlfilter.DNSRequest{},
		URLFilterResult:  &urlfilter.DNSResult{},
		RuleLists:        []*rulelist.Refreshable{blockingRL},
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
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/composite
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkFilter_FilterReqWithRuleLists-16    	  807964	      1904 ns/op	     469 B/op	       8 allocs/op
}
