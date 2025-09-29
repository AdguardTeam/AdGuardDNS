// Package geoip contains implementations of the GeoIP database for AdGuard DNS.
package geoip

import (
	"context"
	"net/netip"

	"github.com/AdguardTeam/golibs/netutil"
)

// Interface is the interface for the GeoIP database that stores the geographic
// data about an IP address.
type Interface interface {
	// SubnetByLocation returns the default subnet for location, if there is
	// one.  If there isn't, n is an unspecified subnet.  fam must be either
	// [netutil.AddrFamilyIPv4] or [netutil.AddrFamilyIPv6].
	SubnetByLocation(
		ctx context.Context,
		l *Location,
		fam netutil.AddrFamily,
	) (n netip.Prefix, err error)

	// Data returns the GeoIP data for ip.  It may use host to get cached GeoIP
	// data if ip is netip.Addr{}.
	Data(ctx context.Context, host string, ip netip.Addr) (l *Location, err error)
}
