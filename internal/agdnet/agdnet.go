// Package agdnet contains network-related utilities.
//
// TODO(a.garipov): Move stuff to netutil.
package agdnet

import (
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

// NormalizeDomain returns lowercased version of the host without the final dot.
//
// TODO(a.garipov): Move to golibs.
func NormalizeDomain(fqdn string) (host string) {
	return strings.ToLower(strings.TrimSuffix(fqdn, "."))
}

// NormalizeQueryDomain returns a lowercased version of the host without the
// final dot, unless the host is ".", in which case it returns the unchanged
// host.  That is the special case to allow matching queries like:
//
//	dig IN NS '.'
func NormalizeQueryDomain(host string) (norm string) {
	if host == "." {
		return host
	}

	return NormalizeDomain(host)
}
