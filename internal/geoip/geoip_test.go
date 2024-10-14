package geoip_test

import (
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/container"
)

// Paths to test data.
const (
	asnPath     = "./testdata/GeoIP2-ISP-Test.mmdb"
	cityPath    = "./testdata/GeoIP2-City-Test.mmdb"
	countryPath = "./testdata/GeoIP2-Country-Test.mmdb"
)

// Common test hosts.
const (
	testHost      = "www.example.com"
	testOtherHost = "other.example.com"
)

// Test ASN data.
var (
	allTopASNs = container.NewMapSet(
		countryTopASNs[geoip.CountryAU],
		countryTopASNs[geoip.CountryJP],
		countryTopASNs[geoip.CountryUS],
	)

	countryTopASNs = map[geoip.Country]geoip.ASN{
		geoip.CountryAU: 1221,
		geoip.CountryJP: 2516,
		geoip.CountryUS: 7922,
	}
)

// Test queries data.  See [ASN], [city], and [country] testing datum.
//
// [ASN]: https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/source-data/GeoIP2-ISP-Test.json
// [city]: https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/source-data/GeoIP2-City-Test.json
// [country]: https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/source-data/GeoIP2-Country-Test.json
const (
	testASN    geoip.ASN = 1221
	testCtry             = geoip.CountryUS
	testCont             = geoip.ContinentNA
	testSubdiv string    = "WA"

	testIPv4SubnetCtry = geoip.CountryUS
	testIPv6SubnetCtry = geoip.CountryJP
)

// testIPWithASN has ASN set to 1221 in the test database.
var testIPWithASN = netip.MustParseAddr("1.128.0.0")

// testIPWithSubdiv has country set to USA and the subdivision set to Washington
// in the city-aware test database.  It has no subdivision in the country-aware
// test database but resolves into USA as well.
var testIPWithSubdiv = netip.MustParseAddr("216.160.83.56")

// testIPWithCountry has country set to Japan in the country-aware test
// database.
var testIPWithCountry = netip.MustParseAddr("2001:218::")

// Subnets for CountrySubnet tests.
var (
	testIPv4CountrySubnet = netip.MustParsePrefix("76.128.0.0/24")
	testIPv6CountrySubnet = netip.MustParsePrefix("240f::/56")
)
