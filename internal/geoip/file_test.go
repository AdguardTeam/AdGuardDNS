package geoip_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFile_Data_cityDB(t *testing.T) {
	conf := &geoip.FileConfig{
		ASNPath:        asnPath,
		CountryPath:    cityPath,
		HostCacheSize:  0,
		IPCacheSize:    1,
		AllTopASNs:     allTopASNs,
		CountryTopASNs: countryTopASNs,
	}

	g, err := geoip.NewFile(conf)
	require.NoError(t, err)

	d, err := g.Data(testHost, testIPWithASN)
	require.NoError(t, err)

	assert.Equal(t, testASN, d.ASN)

	d, err = g.Data(testHost, testIPWithSubdiv)
	require.NoError(t, err)

	assert.Equal(t, testCtry, d.Country)
	assert.Equal(t, testCont, d.Continent)
	assert.Equal(t, testSubdiv, d.TopSubdivision)
}

func TestFile_Data_countryDB(t *testing.T) {
	conf := &geoip.FileConfig{
		ASNPath:        asnPath,
		CountryPath:    countryPath,
		HostCacheSize:  0,
		IPCacheSize:    1,
		AllTopASNs:     allTopASNs,
		CountryTopASNs: countryTopASNs,
	}

	g, err := geoip.NewFile(conf)
	require.NoError(t, err)

	d, err := g.Data(testHost, testIPWithASN)
	require.NoError(t, err)

	assert.Equal(t, testASN, d.ASN)

	d, err = g.Data(testHost, testIPWithSubdiv)
	require.NoError(t, err)

	assert.Equal(t, testCtry, d.Country)
	assert.Equal(t, testCont, d.Continent)
	assert.Empty(t, d.TopSubdivision)
}

func TestFile_Data_hostCache(t *testing.T) {
	conf := &geoip.FileConfig{
		ASNPath:        asnPath,
		CountryPath:    cityPath,
		HostCacheSize:  1,
		IPCacheSize:    1,
		AllTopASNs:     allTopASNs,
		CountryTopASNs: countryTopASNs,
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
	conf := &geoip.FileConfig{
		ASNPath:        asnPath,
		CountryPath:    cityPath,
		HostCacheSize:  0,
		IPCacheSize:    1,
		AllTopASNs:     allTopASNs,
		CountryTopASNs: countryTopASNs,
	}

	g, cErr := geoip.NewFile(conf)
	require.NoError(t, cErr)

	testCases := []struct {
		name    string
		country agd.Country
		want    netip.Prefix
		asn     agd.ASN
		fam     netutil.AddrFamily
	}{{
		name:    "by_asn",
		country: testIPv4SubnetCtry,
		asn:     countryTopASNs[testIPv4SubnetCtry],
		fam:     netutil.AddrFamilyIPv4,
		want:    testIPv4CountrySubnet,
	}, {
		name:    "from_top_countries_v4",
		country: testIPv4SubnetCtry,
		asn:     0,
		fam:     netutil.AddrFamilyIPv4,
		want:    testIPv4CountrySubnet,
	}, {
		name:    "from_top_countries_v6",
		country: testIPv6SubnetCtry,
		asn:     0,
		fam:     netutil.AddrFamilyIPv6,
		want:    testIPv6CountrySubnet,
	}, {
		name:    "from_countries_dict",
		country: agd.CountryBT,
		asn:     0,
		fam:     netutil.AddrFamilyIPv4,
		want:    netip.MustParsePrefix("67.43.156.0/24"),
	}, {
		name:    "not_found",
		country: agd.CountryFR,
		asn:     0,
		fam:     netutil.AddrFamilyIPv4,
		want:    netutil.ZeroPrefix(netutil.AddrFamilyIPv4),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrySubnet, err := g.SubnetByLocation(tc.country, tc.asn, tc.fam)
			require.NoError(t, err)

			assert.Equal(t, tc.want, ctrySubnet)
		})
	}
}

var locSink *agd.Location

var errSink error

func BenchmarkFile_Data(b *testing.B) {
	conf := &geoip.FileConfig{
		ASNPath:        asnPath,
		CountryPath:    cityPath,
		HostCacheSize:  0,
		IPCacheSize:    1,
		AllTopASNs:     geoip.DefaultTopASNs,
		CountryTopASNs: geoip.DefaultCountryTopASNs,
	}

	g, err := geoip.NewFile(conf)
	require.NoError(b, err)

	ipCountry1 := testIPWithCountry

	// Change the eighth byte in testIPWithCountry to create a different address
	// in the same network.
	ipSlice := ipCountry1.AsSlice()
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
	conf := &geoip.FileConfig{
		ASNPath:        asnPath,
		CountryPath:    cityPath,
		HostCacheSize:  0,
		IPCacheSize:    1,
		AllTopASNs:     geoip.DefaultTopASNs,
		CountryTopASNs: geoip.DefaultCountryTopASNs,
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		fileSink, errSink = geoip.NewFile(conf)
	}

	assert.NotNil(b, fileSink)
	assert.NoError(b, errSink)

	// Recent result on MBP 15:
	//
	//	goos: darwin
	//	goarch: amd64
	//	cpu: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz
	//	BenchmarkNewFile-12    2192    532262 ns/op    180929 B/op    5980 allocs/op
}
