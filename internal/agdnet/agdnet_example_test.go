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

func ExampleIsSubdomain() {
	fmt.Printf("%-14s: %5t\n", "same domain", agdnet.IsSubdomain("sub.example.com", "example.com"))
	fmt.Printf("%-14s: %5t\n", "not immediate", agdnet.IsSubdomain("subsub.sub.example.com", "example.com"))

	fmt.Printf("%-14s: %5t\n", "empty", agdnet.IsSubdomain("", ""))
	fmt.Printf("%-14s: %5t\n", "same", agdnet.IsSubdomain("example.com", "example.com"))
	fmt.Printf("%-14s: %5t\n", "dot only", agdnet.IsSubdomain(".example.com", "example.com"))
	fmt.Printf("%-14s: %5t\n", "backwards", agdnet.IsSubdomain("example.com", "sub.example.com"))
	fmt.Printf("%-14s: %5t\n", "other domain", agdnet.IsSubdomain("sub.example.com", "example.org"))
	fmt.Printf("%-14s: %5t\n", "similar 1", agdnet.IsSubdomain("sub.myexample.com", "example.org"))
	fmt.Printf("%-14s: %5t\n", "similar 2", agdnet.IsSubdomain("sub.example.com", "myexample.org"))

	// Output:
	// same domain   :  true
	// not immediate :  true
	// empty         : false
	// same          : false
	// dot only      : false
	// backwards     : false
	// other domain  : false
	// similar 1     : false
	// similar 2     : false
}

func ExampleIsImmediateSubdomain() {
	fmt.Printf("%-14s: %5t\n", "same domain", agdnet.IsImmediateSubdomain("sub.example.com", "example.com"))

	fmt.Printf("%-14s: %5t\n", "empty", agdnet.IsImmediateSubdomain("", ""))
	fmt.Printf("%-14s: %5t\n", "same", agdnet.IsImmediateSubdomain("example.com", "example.com"))
	fmt.Printf("%-14s: %5t\n", "dot only", agdnet.IsImmediateSubdomain(".example.com", "example.com"))
	fmt.Printf("%-14s: %5t\n", "backwards", agdnet.IsImmediateSubdomain("example.com", "sub.example.com"))
	fmt.Printf("%-14s: %5t\n", "other domain", agdnet.IsImmediateSubdomain("sub.example.com", "example.org"))
	fmt.Printf("%-14s: %5t\n", "not immediate", agdnet.IsImmediateSubdomain("subsub.sub.example.com", "example.com"))
	fmt.Printf("%-14s: %5t\n", "similar 1", agdnet.IsSubdomain("sub.myexample.com", "example.org"))
	fmt.Printf("%-14s: %5t\n", "similar 2", agdnet.IsSubdomain("sub.example.com", "myexample.org"))

	// Output:
	// same domain   :  true
	// empty         : false
	// same          : false
	// dot only      : false
	// backwards     : false
	// other domain  : false
	// not immediate : false
	// similar 1     : false
	// similar 2     : false
}
