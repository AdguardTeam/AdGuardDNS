package ecscache

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/miekg/dns"
)

var msgSink *dns.Msg

func BenchmarkMiddleware_Get(b *testing.B) {
	mw := &Middleware{
		cache: agdcache.NewLRU[uint64, *cacheItem](&agdcache.LRUConfig{
			Size: 10,
		}),
		ecsCache: agdcache.NewLRU[uint64, *cacheItem](&agdcache.LRUConfig{
			Size: 10,
		}),
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
	for range b.N {
		msgSink, _ = mw.get(req, cr)
	}
}
