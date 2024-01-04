package composite

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
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

func BenchmarkFilter_FilterWithRuleLists(b *testing.B) {
	blockingRL, err := rulelist.NewFromString(filtertest.BlockRule+"\n", "test", "", 0, false)
	require.NoError(b, err)

	f := New(&Config{
		RuleLists: []*rulelist.Refreshable{blockingRL},
	})

	req := dnsservertest.NewReq(filtertest.ReqFQDN, dns.TypeA, dns.ClassINET)
	ri := &agd.RequestInfo{
		Messages: dnsmsg.NewConstructor(nil, &dnsmsg.BlockingModeNullIP{}, filtertest.Staleness),
		RemoteIP: filtertest.RemoteIP,
		Host:     filtertest.ReqHost,
		QType:    dns.TypeA,
		QClass:   dns.ClassINET,
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		resultSink = f.filterWithRuleLists(ri, filtertest.ReqHost, dns.TypeCNAME, req)
	}

	// Most recent results, on a MBP 14 with Apple M1 Pro chip:
	//
	//	goos: darwin
	//  goarch: arm64
	//  pkg: github.com/AdguardTeam/urlfilter
	//  BenchmarkFilter_FilterWithRuleLists
	//  BenchmarkFilter_FilterWithRuleLists-8   	 1623212	       698.0 ns/op	     161 B/op	       6 allocs/op
}
