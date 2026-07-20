package mainmw

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPFromAnswer(t *testing.T) {
	t.Parallel()

	var ttlSec uint32 = 10

	ipv4Answ := []dns.RR{dnsservertest.NewHTTPS(
		dnsservertest.FQDN,
		ttlSec,
		[]netip.Addr{dnssvctest.DomainAddrIPv4},
		nil,
	)}

	ipv6Answ := []dns.RR{dnsservertest.NewHTTPS(
		dnsservertest.FQDN,
		ttlSec,
		nil,
		[]netip.Addr{dnssvctest.DomainAddrIPv6},
	)}

	testCases := []struct {
		wantIP netip.Addr
		name   string
		answer []dns.RR
	}{{
		name:   "https_no_ips",
		answer: []dns.RR{dnsservertest.NewHTTPS(dnsservertest.FQDN, ttlSec, nil, nil)},
		wantIP: netip.Addr{},
	}, {
		name: "multiple_ips",
		answer: []dns.RR{
			dnsservertest.NewTXT(dnsservertest.FQDN, ttlSec),
			dnsservertest.NewA(dnsservertest.FQDN, ttlSec, dnssvctest.DomainAddrIPv4),
		},
		wantIP: dnssvctest.DomainAddrIPv4,
	}, {
		name:   "https_ipv4",
		answer: ipv4Answ,
		wantIP: dnssvctest.DomainAddrIPv4,
	}, {
		name:   "https_ipv6",
		answer: ipv6Answ,
		wantIP: dnssvctest.DomainAddrIPv6,
	}, {
		name:   "txt",
		answer: []dns.RR{dnsservertest.NewTXT(dnsservertest.FQDN, ttlSec)},
		wantIP: netip.Addr{},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotIP, err := ipFromAnswer(tc.answer)
			require.NoError(t, err)

			assert.Equal(t, tc.wantIP, gotIP)
		})
	}
}
