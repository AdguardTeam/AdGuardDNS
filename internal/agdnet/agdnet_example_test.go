package agdnet_test

import (
	"fmt"
	"net"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/golibs/netutil"
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

func ExampleZeroSubnet() {
	fmt.Printf("%-5s: %9s\n", "ipv4", agdnet.ZeroSubnet(agdnet.AddrFamilyIPv4))
	fmt.Printf("%-5s: %9s\n", "ipv6", agdnet.ZeroSubnet(agdnet.AddrFamilyIPv6))

	func() {
		defer func() { fmt.Println(recover()) }()

		_ = agdnet.ZeroSubnet(42)
	}()

	// Output:
	// ipv4 : 0.0.0.0/0
	// ipv6 :      ::/0
	// agdnet: unsupported addr fam !bad_addr_fam_42
}

func ExampleIPToAddr() {
	ip := net.IP{1, 2, 3, 4}
	addr, err := agdnet.IPToAddr(ip, agdnet.AddrFamilyIPv4)
	fmt.Println(addr, err)

	addr, err = agdnet.IPToAddr(ip, agdnet.AddrFamilyIPv6)
	fmt.Println(addr, err)

	addr, err = agdnet.IPToAddr(nil, agdnet.AddrFamilyIPv4)
	fmt.Println(addr, err)

	// Output:
	// 1.2.3.4 <nil>
	// ::ffff:1.2.3.4 <nil>
	// invalid IP bad ipv4 net.IP <nil>
}

func ExampleIPToAddrNoMapped() {
	addr, err := agdnet.IPToAddrNoMapped(net.IP{1, 2, 3, 4})
	fmt.Println(addr, err)

	addrMapped, err := agdnet.IPToAddrNoMapped(net.IPv4(1, 2, 3, 4))
	fmt.Println(addr, err)
	fmt.Printf("%s == %s is %t\n", addr, addrMapped, addr == addrMapped)

	addr, err = agdnet.IPToAddrNoMapped(net.ParseIP("1234::cdef"))
	fmt.Println(addr, err)

	// Output:
	// 1.2.3.4 <nil>
	// 1.2.3.4 <nil>
	// 1.2.3.4 == 1.2.3.4 is true
	// 1234::cdef <nil>
}

func ExampleIPNetToPrefix() {
	prefix, err := agdnet.IPNetToPrefix(nil, agdnet.AddrFamilyIPv4)
	fmt.Println(prefix, err)

	prefix, err = agdnet.IPNetToPrefix(&net.IPNet{
		IP: nil,
	}, agdnet.AddrFamilyIPv4)
	fmt.Println(prefix, err)

	prefix, err = agdnet.IPNetToPrefix(&net.IPNet{
		IP:   net.IP{1, 2, 3, 0},
		Mask: net.CIDRMask(64, netutil.IPv6BitLen),
	}, agdnet.AddrFamilyIPv4)
	fmt.Println(prefix, err)

	prefix, err = agdnet.IPNetToPrefix(&net.IPNet{
		IP:   net.IP{1, 2, 3, 0},
		Mask: net.CIDRMask(24, netutil.IPv4BitLen),
	}, agdnet.AddrFamilyIPv4)
	fmt.Println(prefix, err)

	// Output:
	// invalid Prefix <nil>
	// invalid Prefix bad ip for subnet <nil>: bad ipv4 net.IP <nil>
	// invalid Prefix bad subnet 1.2.3.0/0
	// 1.2.3.0/24 <nil>
}

func ExampleIPNetToPrefixNoMapped() {
	prefix, err := agdnet.IPNetToPrefixNoMapped(&net.IPNet{
		IP:   net.IP{1, 2, 3, 0},
		Mask: net.CIDRMask(24, netutil.IPv4BitLen),
	})
	fmt.Println(prefix, err)

	prefixMapped, err := agdnet.IPNetToPrefixNoMapped(&net.IPNet{
		IP:   net.IPv4(1, 2, 3, 0),
		Mask: net.CIDRMask(24, netutil.IPv4BitLen),
	})
	fmt.Println(prefix, err)
	fmt.Printf("%s == %s is %t\n", prefix, prefixMapped, prefix == prefixMapped)

	prefix, err = agdnet.IPNetToPrefixNoMapped(&net.IPNet{
		IP:   net.ParseIP("1234::cdef"),
		Mask: net.CIDRMask(64, netutil.IPv6BitLen),
	})
	fmt.Println(prefix, err)

	// Output:
	// 1.2.3.0/24 <nil>
	// 1.2.3.0/24 <nil>
	// 1.2.3.0/24 == 1.2.3.0/24 is true
	// 1234::cdef/64 <nil>
}
