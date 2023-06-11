package dnsservertest_test

import (
	"fmt"
	"net"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

func ExampleNewReq() {
	const nonUniqueID = 1234

	m := dnsservertest.NewReq("example.org.", dns.TypeA, dns.ClassINET, dnsservertest.SectionExtra{
		dnsservertest.NewECSExtra(netutil.IPv4Zero(), uint16(netutil.AddrFamilyIPv4), 0, 0),
	})
	m.Id = nonUniqueID
	fmt.Println(m)

	// Output:
	//
	// ;; opcode: QUERY, status: NOERROR, id: 1234
	// ;; flags:; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
	//
	// ;; OPT PSEUDOSECTION:
	// ; EDNS: version 0; flags:; udp: 0
	// ; SUBNET: 0.0.0.0/0/0
	//
	// ;; QUESTION SECTION:
	// ;example.org.	IN	 A
}

func ExampleNewResp() {
	const (
		nonUniqueID  = 1234
		testFQDN     = "example.org."
		realTestFQDN = "real." + testFQDN
	)

	m := dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET, dnsservertest.SectionExtra{
		dnsservertest.NewECSExtra(netutil.IPv4Zero(), uint16(netutil.AddrFamilyIPv4), 0, 0),
	})
	m.Id = nonUniqueID

	m = dnsservertest.NewResp(dns.RcodeSuccess, m, dnsservertest.SectionAnswer{
		dnsservertest.NewCNAME(testFQDN, 3600, realTestFQDN),
		dnsservertest.NewA(realTestFQDN, 3600, net.IP{1, 2, 3, 4}),
	}, dnsservertest.SectionNs{
		dnsservertest.NewSOA(realTestFQDN, 1000, "ns."+realTestFQDN, "mbox."+realTestFQDN),
		dnsservertest.NewNS(testFQDN, 1000, "ns."+testFQDN),
	}, dnsservertest.SectionExtra{
		m.IsEdns0(),
	})
	fmt.Println(m)

	// Output:
	//
	// ;; opcode: QUERY, status: NOERROR, id: 1234
	// ;; flags: qr ra; QUERY: 1, ANSWER: 2, AUTHORITY: 2, ADDITIONAL: 1
	//
	// ;; OPT PSEUDOSECTION:
	// ; EDNS: version 0; flags:; udp: 0
	// ; SUBNET: 0.0.0.0/0/0
	//
	// ;; QUESTION SECTION:
	// ;example.org.	IN	 A
	//
	// ;; ANSWER SECTION:
	// example.org.	3600	IN	CNAME	real.example.org.
	// real.example.org.	3600	IN	A	1.2.3.4
	//
	// ;; AUTHORITY SECTION:
	// real.example.org.	1000	IN	SOA	ns.real.example.org. mbox.real.example.org. 0 0 0 0 0
	// example.org.	1000	IN	NS	ns.example.org.
}
