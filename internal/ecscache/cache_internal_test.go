package ecscache

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func BenchmarkMiddleware_Get(b *testing.B) {
	mw := &Middleware{
		cache: agdcache.NewLRU[uint64, *cacheItem](&agdcache.LRUConfig{
			Count: 10,
		}),
		ecsCache: agdcache.NewLRU[uint64, *cacheItem](&agdcache.LRUConfig{
			Count: 10,
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

	ctx := context.Background()

	var msg *dns.Msg

	b.ReportAllocs()
	for b.Loop() {
		msg, _ = mw.get(ctx, req, cr)
	}

	assert.Nil(b, msg)

	// Most recent results:
	//
	// goos: darwin
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/ecscache
	// cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	// BenchmarkMiddleware_Get-12    	 5855624	       195.1 ns/op	      16 B/op	       2 allocs/op
}
