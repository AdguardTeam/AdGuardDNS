package geoip_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFile_Data(t *testing.T) {
	var ec agd.ErrorCollector = &agdtest.ErrorCollector{
		OnCollect: func(ctx context.Context, err error) { panic("not implemented") },
	}

	conf := &geoip.FileConfig{
		ErrColl:       ec,
		ASNPath:       asnPath,
		CountryPath:   countryPath,
		HostCacheSize: 0,
		IPCacheSize:   1,
	}

	g, err := geoip.NewFile(conf)
	require.NoError(t, err)

	d, err := g.Data(testHost, testIPWithASN)
	require.NoError(t, err)

	assert.Equal(t, testASN, d.ASN)

	d, err = g.Data(testHost, testIPWithCountry)
	require.NoError(t, err)

	assert.Equal(t, testCtry, d.Country)
	assert.Equal(t, testCont, d.Continent)
}

func TestFile_Data_hostCache(t *testing.T) {
	var ec agd.ErrorCollector = &agdtest.ErrorCollector{
		OnCollect: func(ctx context.Context, err error) { panic("not implemented") },
	}

	conf := &geoip.FileConfig{
		ErrColl:       ec,
		ASNPath:       asnPath,
		CountryPath:   countryPath,
		HostCacheSize: 1,
		IPCacheSize:   1,
	}

	g, err := geoip.NewFile(conf)
	require.NoError(t, err)

	d, err := g.Data(testHost, testIPWithASN)
	require.NoError(t, err)

	assert.Equal(t, testASN, d.ASN)

	d, err = g.Data(testHost, netip.Addr{})
	require.NoError(t, err)

	assert.Equal(t, testASN, d.ASN)

	d, err = g.Data(testOtherHost, netip.Addr{})
	require.NoError(t, err)

	assert.Nil(t, d)
}

func TestFile_SubnetByLocation(t *testing.T) {
	var ec agd.ErrorCollector = &agdtest.ErrorCollector{
		OnCollect: func(ctx context.Context, err error) { panic("not implemented") },
	}

	conf := &geoip.FileConfig{
		ErrColl:       ec,
		ASNPath:       asnPath,
		CountryPath:   countryPath,
		HostCacheSize: 0,
		IPCacheSize:   1,
	}

	g, err := geoip.NewFile(conf)
	require.NoError(t, err)

	// TODO(a.garipov): Actually test ASN queries once we have the data.
	gotIPv4Subnet, err := g.SubnetByLocation(testIPv4SubnetCtry, 0, agdnet.AddrFamilyIPv4)
	require.NoError(t, err)

	assert.Equal(t, testIPv4CountrySubnet, gotIPv4Subnet)

	gotIPv6Subnet, err := g.SubnetByLocation(testIPv6SubnetCtry, 0, agdnet.AddrFamilyIPv6)
	require.NoError(t, err)

	assert.Equal(t, testIPv6CountrySubnet, gotIPv6Subnet)
}

var locSink *agd.Location

var errSink error

func BenchmarkFile_Data(b *testing.B) {
	var ec agd.ErrorCollector = &agdtest.ErrorCollector{
		OnCollect: func(ctx context.Context, err error) { panic("not implemented") },
	}

	conf := &geoip.FileConfig{
		ErrColl:       ec,
		ASNPath:       asnPath,
		CountryPath:   countryPath,
		HostCacheSize: 0,
		IPCacheSize:   1,
	}

	g, err := geoip.NewFile(conf)
	require.NoError(b, err)

	ipCountry1 := testIPWithCountry

	// Change the eighth byte in testIPWithCountry to create a different address
	// in the same network.
	ipSlice := testIPWithCountry.AsSlice()
	ipSlice[7] = 1
	ipCountry2, ok := netip.AddrFromSlice(ipSlice)
	require.True(b, ok)

	b.Run("cache", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			locSink, errSink = g.Data(testHost, testIPWithASN)
		}

		assert.Equal(b, testASN, locSink.ASN)

		assert.NoError(b, errSink)
	})

	b.Run("no_cache", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Alternate between the two IPs to force cache misses.
			if i%2 == 0 {
				locSink, errSink = g.Data(testHost, ipCountry1)
			} else {
				locSink, errSink = g.Data(testHost, ipCountry2)
			}
		}

		assert.NotNil(b, locSink)
		assert.NoError(b, errSink)
	})
}

var fileSink *geoip.File

func BenchmarkNewFile(b *testing.B) {
	var ec agd.ErrorCollector = &agdtest.ErrorCollector{
		OnCollect: func(ctx context.Context, err error) { panic("not implemented") },
	}

	conf := &geoip.FileConfig{
		ErrColl:       ec,
		ASNPath:       asnPath,
		CountryPath:   countryPath,
		HostCacheSize: 0,
		IPCacheSize:   1,
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		fileSink, errSink = geoip.NewFile(conf)
	}

	assert.NotNil(b, fileSink)
	assert.NoError(b, errSink)

	// Recent result on MBP 15
	//   goos: darwin
	//   goarch: amd64
	//   cpu: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz
	//   BenchmarkNewFile-12    2192    532262 ns/op    180929 B/op    5980 allocs/op
}
