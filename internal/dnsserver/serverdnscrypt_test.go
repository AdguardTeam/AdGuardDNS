package dnsserver_test

import (
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestServerDNSCrypt_integration_query(t *testing.T) {
	testCases := []struct {
		handler              dnsserver.Handler
		req                  *dns.Msg
		name                 string
		network              dnsserver.Network
		expectedRecordsCount int
		expectedRCode        int
		expectedTruncated    bool
	}{{
		name:                 "udp_valid_msg",
		network:              dnsserver.NetworkUDP,
		expectedRecordsCount: 1,
		expectedRCode:        dns.RcodeSuccess,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
	}, {
		name:                 "tcp_valid_msg",
		network:              dnsserver.NetworkTCP,
		expectedRecordsCount: 1,
		expectedRCode:        dns.RcodeSuccess,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
	}, {
		// Checks that large responses are getting truncated when
		// sent over UDP
		name:    "udp_truncate_response",
		network: dnsserver.NetworkUDP,
		// Set a handler that generates a large response
		handler: dnsservertest.NewDefaultHandlerWithCount(64),
		// DNSCrypt server removes all records from a truncated response
		expectedRecordsCount: 0,
		expectedRCode:        dns.RcodeSuccess,
		expectedTruncated:    true,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
	}, {
		// Checks that if UDP size is large enough there would be no
		// truncated responses
		name:    "udp_edns0_no_truncate",
		network: dnsserver.NetworkUDP,
		// Set a handler that generates a large response
		handler:              dnsservertest.NewDefaultHandlerWithCount(64),
		expectedRecordsCount: 64,
		expectedRCode:        dns.RcodeSuccess,
		expectedTruncated:    false,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			Extra: []dns.RR{
				&dns.OPT{Hdr: dns.RR_Header{
					Name:   ".",
					Rrtype: dns.TypeOPT,
					Class:  2000, // Set large enough UDPSize here
				}},
			},
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := tc.handler
			if tc.handler == nil {
				handler = dnsservertest.NewDefaultHandler()
			}

			s := dnsservertest.RunDNSCryptServer(t, handler)
			client := &dnscrypt.Client{
				Timeout: 1 * time.Second,
				Net:     string(tc.network),
				UDPSize: 7000, // Make sure that we can read any response
			}

			stamp := dnsstamps.ServerStamp{
				ServerAddrStr: s.ServerAddr,
				ServerPk:      s.ResolverPk,
				ProviderName:  s.ProviderName,
				Proto:         dnsstamps.StampProtoTypeDNSCrypt,
			}

			// Load server info
			ri, err := client.DialStamp(stamp)
			require.NoError(t, err)
			require.NotNil(t, ri)

			res, err := client.Exchange(tc.req, ri)
			require.NoError(t, err)
			require.NotNil(t, res)
			dnsservertest.RequireResponse(
				t,
				tc.req,
				res,
				tc.expectedRecordsCount,
				tc.expectedRCode,
				tc.expectedTruncated,
			)
		})
	}
}
