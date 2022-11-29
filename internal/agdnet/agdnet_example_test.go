package agdnet_test

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
)

func ExampleIsAndroidTLSMetricDomain() {
	anAndroidDomain := "1234-ds.metric.gstatic.com."
	fmt.Printf("%-28s: %5t\n", anAndroidDomain, agdnet.IsAndroidTLSMetricDomain(anAndroidDomain))

	notAnAndroidDomain := "www.example.com."
	fmt.Printf("%-28s: %5t\n", notAnAndroidDomain, agdnet.IsAndroidTLSMetricDomain(notAnAndroidDomain))

	// Output:
	// 1234-ds.metric.gstatic.com. :  true
	// www.example.com.            : false
}
