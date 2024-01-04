package ecscache

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/bluele/gcache"
	"github.com/miekg/dns"
)

var msgSink *dns.Msg

func BenchmarkMiddleware_Get(b *testing.B) {
	mw := &Middleware{
		cache:    gcache.New(10).LRU().Build(),
		ecsCache: gcache.New(10).LRU().Build(),
	}

	const (
		host = "benchmark.example"
		fqdn = host + "."
	)

	req := dnsservertest.NewReq(fqdn, dns.TypeA, dns.ClassINET)
	cr := &cacheRequest{
		host:   host,
		subnet: netip.MustParsePrefix("1.2.3.0/24"),
		qType:  dns.TypeA,
		qClass: dns.ClassINET,
		reqDO:  true,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msgSink, _ = mw.get(req, cr)
	}
}
