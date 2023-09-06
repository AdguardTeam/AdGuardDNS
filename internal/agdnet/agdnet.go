// Package agdnet contains network-related utilities.
//
// TODO(a.garipov): Move stuff to netutil.
package agdnet

import (
	"fmt"
	"net/netip"
	"strings"
)

// These are suffixes of the FQDN in DNS queries for metrics that the DNS
// resolver of the Android operating system seems to send a lot and because of
// that we apply special rules to these queries.  Check out Android code to see
// how it's used: https://cs.android.com/search?q=ds.metric.gstatic.com
const (
	androidMetricFQDNSuffix = "-ds.metric.gstatic.com."

	androidMetricDoTFQDNSuffix = "-dnsotls" + androidMetricFQDNSuffix
	androidMetricDoHFQDNSuffix = "-dnsohttps" + androidMetricFQDNSuffix
)

// androidMetricDoTReplacementFQDN and androidMetricDoHReplacementFQDN are
// hosts used to rewrite queries to domains ending with [androidMetricFQDNSuffix].
// We do this in order to cache all these queries as a single record and
// save some resources on this.
const (
	androidMetricDoTReplacementFQDN = "00000000-dnsotls" + androidMetricFQDNSuffix
	androidMetricDoHReplacementFQDN = "000000-dnsohttps" + androidMetricFQDNSuffix
)

// AndroidMetricDomainReplacement returns an empty string if fqdn is not ending with
// androidMetricFQDNSuffix.  Otherwise it returns an appropriate replacement
// domain name.
func AndroidMetricDomainReplacement(fqdn string) (repl string) {
	fqdn = strings.ToLower(fqdn)

	if !strings.HasSuffix(fqdn, androidMetricFQDNSuffix) {
		return ""
	}

	if strings.HasSuffix(fqdn, androidMetricDoHFQDNSuffix) {
		return androidMetricDoHReplacementFQDN
	} else if strings.HasSuffix(fqdn, androidMetricDoTFQDNSuffix) {
		return androidMetricDoTReplacementFQDN
	}

	return ""
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

// NormalizeDomain returns lowercased version of the host without the final dot.
//
// TODO(a.garipov): Move to golibs.
func NormalizeDomain(fqdn string) (host string) {
	return strings.ToLower(strings.TrimSuffix(fqdn, "."))
}
