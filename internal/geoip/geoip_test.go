package geoip_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
)

func TestMain(m *testing.M) {
	agdtest.DiscardLogOutput(m)
}

// Paths to test data.
const (
	asnPath     = "./testdata/GeoLite2-ASN-Test.mmdb"
	countryPath = "./testdata/GeoIP2-Country-Test.mmdb"
)

// Common test hosts.
const (
	testHost      = "www.example.com"
	testOtherHost = "other.example.com"
)

// Test data.  See https://github.com/maxmind/MaxMind-DB/blob/2bf1713b3b5adcb022cf4bb77eb0689beaadcfef/source-data/GeoLite2-ASN-Test.json
// and https://github.com/maxmind/MaxMind-DB/blob/2bf1713b3b5adcb022cf4bb77eb0689beaadcfef/source-data/GeoIP2-Country-Test.json.
const (
	testASN  agd.ASN       = 1221
	testCtry agd.Country   = agd.CountryJP
	testCont agd.Continent = agd.ContinentAS

	testIPv4SubnetCtry = agd.CountryUS
	testIPv6SubnetCtry = agd.CountryJP
)

// testIPWithASN has ASN set to 1221 in the test database.
var testIPWithASN = netip.MustParseAddr("1.128.0.0")

// testIPWithCountry has country set to Japan in the test database.
var testIPWithCountry = netip.MustParseAddr("2001:218::")

// Subnets for CountrySubnet tests.
var (
	testIPv4CountrySubnet = netip.MustParsePrefix("50.114.0.0/24")

	// TODO(a.garipov): Either find a better subnet and country that don't
	// trigger the ASN optimizations or just remove this one completely.
	//
	// testIPv6CountrySubnet = netip.MustParsePrefix("2001:218::/32")

	testIPv6CountrySubnet = netip.MustParsePrefix("240f::/56")
)
