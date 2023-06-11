package agdnet_test

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
)

func ExampleAndroidMetricDomainReplacement() {
	printResult := func(input string) {
		fmt.Printf("%-42q: %q\n", input, agdnet.AndroidMetricDomainReplacement(input))
	}

	anAndroidDomain := "12345678-dnsotls-ds.metric.gstatic.com."
	printResult(anAndroidDomain)

	anAndroidDomain = "123456-dnsohttps-ds.metric.gstatic.com."
	printResult(anAndroidDomain)

	notAndroidDomain := "example.com"
	printResult(notAndroidDomain)

	// Output:
	// "12345678-dnsotls-ds.metric.gstatic.com." : "00000000-dnsotls-ds.metric.gstatic.com."
	// "123456-dnsohttps-ds.metric.gstatic.com." : "000000-dnsohttps-ds.metric.gstatic.com."
	// "example.com"                             : ""
}
