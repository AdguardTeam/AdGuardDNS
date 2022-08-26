// Package agdnet contains network-related utilities.
//
// TODO(a.garipov): Move stuff to netutil.
package agdnet

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// AddrFamily is an IANA address family number.
type AddrFamily uint16

// IANA address family numbers.
//
// See https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml.
const (
	AddrFamilyNone AddrFamily = 0
	AddrFamilyIPv4 AddrFamily = 1
	AddrFamilyIPv6 AddrFamily = 2
)

// String implements the fmt.Stringer interface for AddrFamily.
func (f AddrFamily) String() (s string) {
	switch f {
	case AddrFamilyNone:
		return "none"
	case AddrFamilyIPv4:
		return "ipv4"
	case AddrFamilyIPv6:
		return "ipv6"
	default:
		return fmt.Sprintf("!bad_addr_fam_%d", f)
	}
}

// androidMetricFQDNSuffix is the suffix of the FQDN in DNS queries for
// metrics that the DNS resolver of the Android operating system seems to
// send a lot and because of that we apply special rules to these queries.
// Check out Android code to see how it's used:
// https://cs.android.com/search?q=ds.metric.gstatic.com
const androidMetricFQDNSuffix = "-ds.metric.gstatic.com."

// IsAndroidTLSMetricDomain returns true if the specified domain is the
// Android's DNS-over-TLS metrics domain.
func IsAndroidTLSMetricDomain(fqdn string) (ok bool) {
	fqdnLen := len(fqdn)
	sufLen := len(androidMetricFQDNSuffix)

	return fqdnLen > sufLen && strings.EqualFold(fqdn[fqdnLen-sufLen:], androidMetricFQDNSuffix)
}

// IsSubdomain returns true if domain is a subdomain of top.
func IsSubdomain(domain, top string) (ok bool) {
	return len(domain) > len(top)+1 &&
		strings.HasSuffix(domain, top) &&
		domain[len(domain)-len(top)-1] == '.'
}

// IsImmediateSubdomain returns true if domain is an immediate subdomain of top.
//
// TODO(a.garipov): Move to netutil.
func IsImmediateSubdomain(domain, top string) (ok bool) {
	return IsSubdomain(domain, top) &&
		strings.Count(domain, ".") == strings.Count(top, ".")+1
}

// ZeroSubnet returns an IP subnet with prefix 0 and all bytes of the IP address
// set to 0.  fam must be either AddrFamilyIPv4 or AddrFamilyIPv6.
//
// TODO(a.garipov): Move to netutil.
func ZeroSubnet(fam AddrFamily) (n netip.Prefix) {
	switch fam {
	case AddrFamilyIPv4:
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	case AddrFamilyIPv6:
		return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	default:
		panic(fmt.Errorf("agdnet: unsupported addr fam %s", fam))
	}
}

// IPNetToPrefix is a helper that converts a *net.IPNet into a netip.Prefix.  If
// subnet is nil, it returns netip.Prefix{}.  fam must be either AddrFamilyIPv4
// or AddrFamilyIPv6.
func IPNetToPrefix(subnet *net.IPNet, fam AddrFamily) (p netip.Prefix, err error) {
	if subnet == nil {
		return netip.Prefix{}, nil
	}

	addr, err := IPToAddr(subnet.IP, fam)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("bad ip for subnet %v: %w", subnet, err)
	}

	ones, _ := subnet.Mask.Size()
	p = netip.PrefixFrom(addr, ones)
	if !p.IsValid() {
		return netip.Prefix{}, fmt.Errorf("bad subnet %v", subnet)
	}

	return p, nil
}

// IPNetToPrefixNoMapped is like IPNetToPrefix but it detects the address family
// automatically by assuming that every IPv6-mapped IPv4 address is actually an
// IPv4 address.  Do not use IPNetToPrefixNoMapped where this assumption isn't
// safe.
func IPNetToPrefixNoMapped(subnet *net.IPNet) (p netip.Prefix, err error) {
	if subnet == nil {
		return netip.Prefix{}, nil
	}

	if ip4 := subnet.IP.To4(); ip4 != nil {
		subnet.IP = ip4

		return IPNetToPrefix(subnet, AddrFamilyIPv4)
	}

	return IPNetToPrefix(subnet, AddrFamilyIPv6)
}

// IPToAddr converts a net.IP into a netip.Addr of the given family and returns
// a meaningful error.  fam must be either AddrFamilyIPv4 or AddrFamilyIPv6.
func IPToAddr(ip net.IP, fam AddrFamily) (addr netip.Addr, err error) {
	switch fam {
	case AddrFamilyIPv4:
		// Make sure that we use the IPv4 form of the address to make sure that
		// netip.Addr doesn't turn out to be an IPv6 one when it really should
		// be an IPv4 one.
		ip4 := ip.To4()
		if ip4 == nil {
			return netip.Addr{}, fmt.Errorf("bad ipv4 net.IP %v", ip)
		}

		ip = ip4
	case AddrFamilyIPv6:
		// Again, make sure that we use the correct form according to the
		// address family.
		ip = ip.To16()
	default:
		panic(fmt.Errorf("agdnet: unsupported addr fam %s", fam))
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("bad net.IP value %v", ip)
	}

	return addr, nil
}

// IPToAddrNoMapped is like IPToAddr but it detects the address family
// automatically by assuming that every IPv6-mapped IPv4 address is actually an
// IPv4 address.  Do not use IPToAddrNoMapped where this assumption isn't safe.
func IPToAddrNoMapped(ip net.IP) (addr netip.Addr, err error) {
	if ip4 := ip.To4(); ip4 != nil {
		return IPToAddr(ip4, AddrFamilyIPv4)
	}

	return IPToAddr(ip, AddrFamilyIPv6)
}

// ParseSubnets parses IP networks, including single-address ones, from strings.
func ParseSubnets(strs ...string) (subnets []netip.Prefix, err error) {
	subnets = make([]netip.Prefix, len(strs))
	for i, s := range strs {
		// Detect if this is a CIDR or an IP early, so that the path to
		// returning an error is shorter.
		if strings.Contains(s, "/") {
			subnets[i], err = netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("subnet at idx %d: %w", i, err)
			}

			continue
		}

		var ip netip.Addr
		ip, err = netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("ip at idx %d: %w", i, err)
		}

		subnets[i] = netip.PrefixFrom(ip, ip.BitLen())
	}

	return subnets, nil
}
