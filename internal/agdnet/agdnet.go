// Package agdnet contains network-related utilities.
//
// TODO(a.garipov): Move stuff to netutil.
package agdnet

import (
	"fmt"
	"net/netip"
	"strings"
)

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
