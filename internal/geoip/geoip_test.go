package geoip_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/testutil"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// Paths to test data.
const (
	asnPath     = "./testdata/GeoLite2-ASN-Test.mmdb"
	cityPath    = "./testdata/GeoIP2-City-Test.mmdb"
	countryPath = "./testdata/GeoIP2-Country-Test.mmdb"
)

// Common test hosts.
const (
	testHost      = "www.example.com"
	testOtherHost = "other.example.com"
)

// Test data.  See [ASN], [city], and [country] testing datum.
//
// [ASN]: https://github.com/maxmind/MaxMind-DB/blob/2bf1713b3b5adcb022cf4bb77eb0689beaadcfef/source-data/GeoLite2-ASN-Test.json
// [city]: https://github.com/maxmind/MaxMind-DB/blob/2bf1713b3b5adcb022cf4bb77eb0689beaadcfef/source-data/GeoIP2-City-Test.json
// [country]: https://github.com/maxmind/MaxMind-DB/blob/2bf1713b3b5adcb022cf4bb77eb0689beaadcfef/source-data/GeoIP2-Country-Test.json
const (
	testASN    agd.ASN       = 1221
	testCtry   agd.Country   = agd.CountryUS
	testCont   agd.Continent = agd.ContinentNA
	testSubdiv string        = "WA"

	testIPv4SubnetCtry = agd.CountryUS
	testIPv6SubnetCtry = agd.CountryJP
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

	// TODO(a.garipov): Either find a better subnet and country that don't
	// trigger the ASN optimizations or just remove this one completely.
	//
	// testIPv6CountrySubnet = netip.MustParsePrefix("2001:218::/32")

	testIPv6CountrySubnet = netip.MustParsePrefix("240f::/56")
)
