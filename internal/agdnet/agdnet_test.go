package agdnet_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/publicsuffix"
)

// Common subnets for tests.
var (
	testSubnetIPv4 = netip.MustParsePrefix("1.2.3.0/24")
	testSubnetIPv6 = netip.MustParsePrefix("1234:5678::/64")
)

func TestAppendSubdomains(t *testing.T) {
	testCases := []struct {
		name         string
		domain       string
		want         []string
		subDomainNum int
	}{{
		name:         "all_sub_domains",
		domain:       "example.a.b.c.org",
		subDomainNum: 5,
		want: []string{
			"c.org",
			"b.c.org",
			"a.b.c.org",
			"example.a.b.c.org",
		},
	}, {
		name:         "no_sub_domains",
		domain:       "org",
		subDomainNum: 100,
		want:         []string{},
	}, {
		name:         "limit_sub_domains",
		domain:       "example.a.b.c.org",
		subDomainNum: 3,
		want: []string{
			"c.org",
			"b.c.org",
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := agdnet.AppendSubdomains(nil, tc.domain, tc.subDomainNum, publicsuffix.List)
			assert.ElementsMatch(t, tc.want, actual)
		})
	}
}

func BenchmarkAppendSubdomains(b *testing.B) {
	benchCases := []struct {
		name   string
		domain string
		num    int
	}{{
		name:   "many_sub_domains",
		domain: "example.a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.org",
		num:    100,
	}, {
		name:   "no_sub_domains",
		domain: "org",
		num:    100,
	}, {
		name:   "limit_sub_domains",
		domain: "example.a.b.c.org",
		num:    3,
	}}

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()

			// Warmup to fill the slices.
			got := agdnet.AppendSubdomains(nil, bc.domain, bc.num, publicsuffix.List)

			for b.Loop() {
				got = agdnet.AppendSubdomains(got[:0], bc.domain, bc.num, publicsuffix.List)
			}
		})
	}

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/agdnet
	//	cpu: Apple M3
	//	BenchmarkAppendSubdomains/many_sub_domains-8         	 3826170	       313.4 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkAppendSubdomains/no_sub_domains-8           	20443263	        58.75 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkAppendSubdomains/limit_sub_domains-8        	10685626	       112.2 ns/op	       0 B/op	       0 allocs/op
}
