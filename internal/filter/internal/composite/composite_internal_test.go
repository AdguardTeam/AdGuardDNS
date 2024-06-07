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

func BenchmarkFilter_FilterReqWithRuleLists(b *testing.B) {
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

	for range b.N {
		resultSink = f.filterReqWithRuleLists(ri, req)
	}

	// Most recent results, on a ThinkPad X13 with a Ryzen Pro 7 CPU:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/composite
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkFilter_FilterWithRuleLists-16    	  464508	      2449 ns/op	     162 B/op	       6 allocs/op
}
