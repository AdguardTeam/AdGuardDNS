// Package geoip contains implementations of the GeoIP database for AdGuard DNS.
package geoip

import (
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/netutil"
)

// Interface is the interface for the GeoIP database that stores the geographic
// data about an IP address.
type Interface interface {
	// SubnetByLocation returns the default subnet for country c and ASN a, if
	// there is one.  If there isn't, n is an unspecified subnet.  fam must be
	// either [netutil.AddrFamilyIPv4] or [netutil.AddrFamilyIPv6].
	SubnetByLocation(c agd.Country, a agd.ASN, fam netutil.AddrFamily) (n netip.Prefix, err error)

	// Data returns the GeoIP data for ip.  It may use host to get cached GeoIP
	// data if ip is netip.Addr{}.
	Data(host string, ip netip.Addr) (l *agd.Location, err error)
}
