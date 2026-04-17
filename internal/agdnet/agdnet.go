// Package agdnet contains network-related utilities.
//
// TODO(a.garipov): Move stuff to netutil.
package agdnet

import (
	"fmt"
	"net/http/cookiejar"
	"strings"

	"github.com/AdguardTeam/golibs/netutil"
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

// androidMetricDoTReplacementFQDN and androidMetricDoHReplacementFQDN are hosts
// used to rewrite queries to domains ending with [androidMetricFQDNSuffix].
// This is done in order to cache all these queries as a single record and save
// some resources on this.
const (
	androidMetricDoTReplacementFQDN = "00000000-dnsotls" + androidMetricFQDNSuffix
	androidMetricDoHReplacementFQDN = "000000-dnsohttps" + androidMetricFQDNSuffix
)

// AndroidMetricDomainReplacement returns an empty string if fqdn is not ending
// with androidMetricFQDNSuffix.  Otherwise it returns an appropriate
// replacement domain name.
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

// AppendSubdomains appends all subdomains to orig and limits result length with
// subDomainNum.  publicList must not be nil.
func AppendSubdomains(
	orig []string,
	domain string,
	subDomainNum int,
	publicList cookiejar.PublicSuffixList,
) (sub []string) {
	sub = orig
	pubSuf := publicList.PublicSuffix(domain)

	dotsNum := 0
	i := strings.LastIndexFunc(domain, func(r rune) (ok bool) {
		if r == '.' {
			dotsNum++
		}

		return dotsNum == subDomainNum
	})
	if i != -1 {
		domain = domain[i+1:]
	}

	sub = netutil.AppendSubdomains(sub, domain)
	for i, s := range sub {
		if s == pubSuf {
			sub = sub[:i]

			break
		}
	}

	return sub
}

// EffectiveTLDPlusOne returns the effective top level domain plus one more
// label. For example, the eTLD+1 for "foo.bar.golang.org" is "golang.org".
//
// TODO(e.burkov):  Move to golibs.
func EffectiveTLDPlusOne(list cookiejar.PublicSuffixList, domain string) (d string, err error) {
	if strings.HasPrefix(domain, ".") ||
		strings.HasSuffix(domain, ".") ||
		strings.Contains(domain, "..") {
		return "", fmt.Errorf("publicsuffix: empty label in domain %q", domain)
	}

	ps := list.PublicSuffix(domain)
	if len(domain) <= len(ps) {
		return "", fmt.Errorf("publicsuffix: cannot derive eTLD+1 for domain %q", domain)
	}

	i := len(domain) - len(ps) - 1
	if domain[i] != '.' {
		return "", fmt.Errorf("publicsuffix: invalid public suffix %q for domain %q", ps, domain)
	}

	return domain[1+strings.LastIndex(domain[:i], "."):], nil
}
