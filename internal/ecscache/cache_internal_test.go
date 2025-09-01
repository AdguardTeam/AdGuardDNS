package ecscache

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func BenchmarkMiddleware(b *testing.B) {
	mw := NewMiddleware(&MiddlewareConfig{
		Metrics:      EmptyMetrics{},
		Clock:        timeutil.SystemClock{},
		Cloner:       agdtest.NewCloner(),
		Logger:       slogutil.NewDiscardLogger(),
		CacheManager: agdcache.EmptyManager{},
		GeoIP:        agdtest.NewGeoIP(),
		NoECSCount:   100,
		ECSCount:     100,
	})

	const (
		host = "benchmark.example"
		fqdn = host + "."

		defaultTTL uint32 = 3600
	)

	reqAddr := netip.MustParseAddr("1.2.3.4")

	req := dnsservertest.NewReq(fqdn, dns.TypeA, dns.ClassINET)
	cr := &cacheRequest{
		host:   host,
		subnet: netip.MustParsePrefix("1.2.3.0/24"),
		qType:  dns.TypeA,
		qClass: dns.ClassINET,
		reqDO:  true,
	}
	resp := dnsservertest.NewResp(dns.RcodeSuccess, req, dnsservertest.SectionAnswer{
		dnsservertest.NewA(host, defaultTTL, reqAddr),
	})

	ctx := context.Background()

	var msg *dns.Msg

	b.ReportAllocs()
	for b.Loop() {
		mw.set(resp, cr, true)

		msg, _ = mw.get(ctx, req, cr)
	}

	assert.NotNil(b, msg)

	// Most recent results:
	//
	// goos: darwin
	// goarch: arm64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/ecscache
	// cpu: Apple M1 Pro
	// BenchmarkMiddleware_Get-8   	 1647064	       726.8 ns/op	     568 B/op	      12 allocs/op
}
