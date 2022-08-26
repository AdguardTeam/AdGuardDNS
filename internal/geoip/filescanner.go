package geoip

import (
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/golibs/log"
	"github.com/oschwald/maxminddb-golang"
)

// GeoIP Database File Scanning

// helper constants for filtering the country subnets based on recommendations
// from RFC 6177, https://developers.google.com/speed/public-dns/docs/ecs,
// and our experience with ECS.
//
// Some authoritative servers return SERVFAIL to NS queries when the ECS data
// doesn't contain a valid, announced subnet, so AdGuard DNS cannot just trust
// the data provided by the GeoIP database, which may be merged to save space.
//
// For example, if an organization (here, Hong Kong Telecommunications)
// announces both 112.118.0.0/16 and 112.119.0.0/16 then the GeoIP database can
// merge them into 112.118.0.0/15.  But NS queries with this new merged subnet
// fail with SERVFAIL:
//
//	dig IN NS 'gslb-hk1.hsbc.com' @8.8.8.8 +adflag +subnet=112.118.0.0/15
//
// On the other hand, using a narrower subnet that is contained within both
// announced networks works:
//
//	dig IN NS 'gslb-hk1.hsbc.com' @8.8.8.8 +adflag +subnet=112.118.0.0/24
const (
	desiredIPv4SubnetLength = 24
	desiredIPv6SubnetLength = 56
)

// resetTopASNSubnets resets the IPv4 and IPv6 top ASN subnet maps.  For each
// ASN in the set of top ASNs, as defined by allTopASNs, the subnet of a desired
// length is chosen (see desiredIPv4SubnetLength and desiredIPv6SubnetLength).
//
// If an ASN only has a subnet that is broader than the desired length, that
// subnet is replaced with one of the desired length with the newly-significant
// bits set to zero.
//
// TODO(a.garipov): Consider merging with resetCountrySubnets.
func resetTopASNSubnets(r *maxminddb.Reader) (ipv4, ipv6 asnSubnets, err error) {
	ipv4, ipv6 = asnSubnets{}, asnSubnets{}

	nets := r.Networks(maxminddb.SkipAliasedNetworks)
	for nets.Next() {
		var asn agd.ASN
		var subnet netip.Prefix
		asn, subnet, err = subnetASNData(nets)
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return nil, nil, err
		} else if _, ok := allTopASNs[asn]; !ok {
			continue
		}

		if subnet.Addr().Is4() {
			replaceSubnet(ipv4, asn, subnet, desiredIPv4SubnetLength)
		} else {
			replaceSubnet(ipv6, asn, subnet, desiredIPv6SubnetLength)
		}

	}

	err = nets.Err()
	if err != nil {
		return nil, nil, fmt.Errorf("reading: %w", err)
	}

	applyTopASNSubnetHacks(ipv4, agdnet.AddrFamilyIPv4)
	applyTopASNSubnetHacks(ipv6, agdnet.AddrFamilyIPv6)

	log.Debug("geoip: got ipv4 top asn subnets %v", ipv4)
	log.Debug("geoip: got ipv6 top asn subnets %v", ipv6)

	return ipv4, ipv6, nil
}

// subnetASNData returns the ASN and subnet of the network at which nets
// currently points.
func subnetASNData(nets *maxminddb.Networks) (asn agd.ASN, subnet netip.Prefix, err error) {
	var res asnResult
	n, err := nets.Network(&res)
	if err != nil {
		return 0, netip.Prefix{}, fmt.Errorf("getting subnet and asn: %w", err)
	}

	// Assume that there are no actual IPv6-mapped IPv4 addresses in the GeoIP
	// database.
	subnet, err = agdnet.IPNetToPrefixNoMapped(n)
	if err != nil {
		return 0, netip.Prefix{}, fmt.Errorf("converting subnet: %w", err)
	}

	return agd.ASN(res.ASN), subnet, nil
}

// replaceSubnet adds subnet to subnets, possibly replacing the previous one,
// depending on presence and characteristics of the subnet already present in
// subnets for the given key.
func replaceSubnet[K comparable, M ~map[K]netip.Prefix](
	subnets M,
	key K,
	subnet netip.Prefix,
	desiredLength int,
) {
	prev, ok := subnets[key]
	if !ok {
		if subnet.Bits() > desiredLength {
			// Don't add the subnet if it's not broad enough.
			return
		}
	} else if dist(prev.Bits(), desiredLength) < dist(subnet.Bits(), desiredLength) {
		// Don't add the subnet if the current subnet's length is closer to the
		// desired one than that of the new subnet.
		return
	}

	subnets[key] = subnet
}

// dist returns the absolute difference between two non-negative integers a and
// b.  d is never negative.
func dist(a, b int) (d int) {
	if a < 0 || b < 0 {
		panic(fmt.Errorf("dist: bad parameters %d and %d", a, b))
	}

	d = a - b
	if d < 0 {
		return -d
	}

	return d
}

// applyTopASNSubnetHacks modifies the data in subnets based on the previous
// experience and user reports.  It also make sure that all items in subnets
// have the desired length for their protocol.  subnets must not be nil.  fam
// must be either agdnet.AddrFamilyIPv4 or agdnet.AddrFamilyIPv6.
func applyTopASNSubnetHacks(subnets asnSubnets, fam agdnet.AddrFamily) {
	var desiredLength int
	switch fam {
	case agdnet.AddrFamilyIPv4:
		// We've got complaints from Moscow Megafon users that they cannot use
		// the YouTube app on Android and iOS when we use a different subnet.
		// It appears that the IPs for domain "youtubei.googleapis.com" are
		// indeed not available in their network unless this network is used in
		// the ECS option.
		subnets[25159] = netip.MustParsePrefix("178.176.72.0/24")
		desiredLength = desiredIPv4SubnetLength
	case agdnet.AddrFamilyIPv6:
		// TODO(a.garipov): Add more if we find them.

		desiredLength = desiredIPv6SubnetLength
	default:
		panic(fmt.Errorf("geoip: unsupported addr fam %s", fam))
	}

	for asn, n := range subnets {
		if n.Bits() < desiredLength {
			subnets[asn] = netip.PrefixFrom(n.Addr(), desiredLength)
		}
	}
}

// resetCountrySubnets resets the IPv4 and IPv6 country subnet maps.  For each
// country, the subnet of a desired length is chosen (see
// desiredIPv4SubnetLength and desiredIPv6SubnetLength).
//
// If a country only has a subnet that is broader than the desired length, that
// subnet is replaced with one of the desired length with the newly-significant
// bits set to zero.
//
// TODO(a.garipov): Consider merging with resetTopASNSubnets.
func resetCountrySubnets(r *maxminddb.Reader) (ipv4, ipv6 countrySubnets, err error) {
	ipv4, ipv6 = countrySubnets{}, countrySubnets{}

	nets := r.Networks(maxminddb.SkipAliasedNetworks)
	for nets.Next() {
		var c agd.Country
		var subnet netip.Prefix
		c, subnet, err = subnetCountryData(nets)
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return nil, nil, err
		} else if c == agd.CountryNone {
			continue
		}

		if subnet.Addr().Is4() {
			replaceSubnet(ipv4, c, subnet, desiredIPv4SubnetLength)
		} else {
			replaceSubnet(ipv6, c, subnet, desiredIPv6SubnetLength)
		}
	}

	err = nets.Err()
	if err != nil {
		return nil, nil, fmt.Errorf("reading: %w", err)
	}

	applyCountrySubnetHacks(ipv4, agdnet.AddrFamilyIPv4)
	applyCountrySubnetHacks(ipv6, agdnet.AddrFamilyIPv6)

	log.Debug("geoip: got ipv4 country subnets %v", ipv4)
	log.Debug("geoip: got ipv6 country subnets %v", ipv6)

	return ipv4, ipv6, nil
}

// applyCountrySubnetHacks modifies the data in subnets based on the previous
// experience and user reports.  It also make sure that all items in subnets
// have the desired length for their protocol.  subnets must not be nil.  fam
// must be either agdnet.AddrFamilyIPv4 or agdnet.AddrFamilyIPv6.
func applyCountrySubnetHacks(subnets countrySubnets, fam agdnet.AddrFamily) {
	var desiredLength int
	switch fam {
	case agdnet.AddrFamilyIPv4:
		// TODO(a.garipov): Add more if we find them.

		desiredLength = desiredIPv4SubnetLength
	case agdnet.AddrFamilyIPv6:
		// TODO(a.garipov): Add more if we find them.

		desiredLength = desiredIPv6SubnetLength
	default:
		panic(fmt.Errorf("geoip: unsupported addr fam %s", fam))
	}

	for c, n := range subnets {
		if n.Bits() < desiredLength {
			subnets[c] = netip.PrefixFrom(n.Addr(), desiredLength)
		}
	}
}

// subnetCountryData returns the country and subnet of the network at which nets
// currently points.
func subnetCountryData(nets *maxminddb.Networks) (c agd.Country, subnet netip.Prefix, err error) {
	var res countryResult
	n, err := nets.Network(&res)
	if err != nil {
		return agd.CountryNone, netip.Prefix{}, fmt.Errorf("getting subnet and country: %w", err)
	}

	// Assume that there are no actual IPv6-mapped IPv4 addresses in the GeoIP
	// database.
	subnet, err = agdnet.IPNetToPrefixNoMapped(n)
	if err != nil {
		return agd.CountryNone, netip.Prefix{}, fmt.Errorf("converting subnet: %w", err)
	}

	ctryStr := res.Country.ISOCode
	if ctryStr == "" {
		return agd.CountryNone, netip.Prefix{}, nil
	}

	c, err = agd.NewCountry(ctryStr)
	if err != nil {
		return agd.CountryNone, netip.Prefix{}, fmt.Errorf("converting country: %w", err)
	}

	return c, subnet, nil
}
