package agd

// Location Types And Constants

// Location represents the GeoIP location data about an IP address.
type Location struct {
	// Country is the country whose subnets contain the IP address.
	Country Country

	// Continent is the continent whose subnets contain the IP address.
	Continent Continent

	// TopSubdivision is the ISO-code of the political subdivision of a country
	// whose subnets contain the IP address.  This field may be empty.
	TopSubdivision string

	// ASN is the number of the autonomous system whose subnets contain the IP
	// address.
	ASN ASN
}

// ASN is the autonomous system number of an IP address.
//
// See also https://datatracker.ietf.org/doc/html/rfc7300.
type ASN uint32

// Continent represents a continent code used by MaxMind.
type Continent string

// Continent code constants.
const (
	// ContinentNone is an unknown continent code.
	ContinentNone Continent = ""
	// ContinentAF is Africa.
	ContinentAF Continent = "AF"
	// ContinentAN is Antarctica.
	ContinentAN Continent = "AN"
	// ContinentAS is Asia.
	ContinentAS Continent = "AS"
	// ContinentEU is Europe.
	ContinentEU Continent = "EU"
	// ContinentNA is North America.
	ContinentNA Continent = "NA"
	// ContinentOC is Oceania.
	ContinentOC Continent = "OC"
	// ContinentSA is South America.
	ContinentSA Continent = "SA"
)

// NewContinent converts s into a Continent while also validating it.  Prefer to
// use this instead of a plain conversion.
func NewContinent(s string) (c Continent, err error) {
	switch c = Continent(s); c {
	case
		ContinentAF,
		ContinentAN,
		ContinentAS,
		ContinentEU,
		ContinentNA,
		ContinentOC,
		ContinentSA,
		ContinentNone:
		return c, nil
	default:
		return ContinentNone, &NotAContinentError{Code: s}
	}
}
