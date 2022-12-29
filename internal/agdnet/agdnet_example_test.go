package agdnet_test

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
)

func ExampleAndroidMetricDomainReplacement() {
	anAndroidDomain := "12345678-dnsotls-ds.metric.gstatic.com."
	fmt.Printf("%-42q: %q\n", anAndroidDomain, agdnet.AndroidMetricDomainReplacement(anAndroidDomain))

	anAndroidDomain = "123456-dnsohttps-ds.metric.gstatic.com."
	fmt.Printf("%-42q: %q\n", anAndroidDomain, agdnet.AndroidMetricDomainReplacement(anAndroidDomain))

	notAndroidDomain := "example.com"
	fmt.Printf("%-42q: %q\n", notAndroidDomain, agdnet.AndroidMetricDomainReplacement(notAndroidDomain))

	// Output:
	// "12345678-dnsotls-ds.metric.gstatic.com." : "00000000-dnsotls-ds.metric.gstatic.com."
	// "123456-dnsohttps-ds.metric.gstatic.com." : "000000-dnsohttps-ds.metric.gstatic.com."
	// "example.com"                             : ""
}
