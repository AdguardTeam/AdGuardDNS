package dnsserver_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestServerDNS_StartShutdown(t *testing.T) {
	_, _ = dnsservertest.RunDNSServer(t, dnsservertest.DefaultHandler())
}

func TestServerDNS_integration_query(t *testing.T) {
	testCases := []struct {
		name    string
		network dnsserver.Network
		req     *dns.Msg
		// if nil, use defaultTestHandler
		handler              dnsserver.Handler
		expectedRecordsCount int
		expectedRCode        int
		expectedTruncated    bool
		expectedMsg          func(t *testing.T, m *dns.Msg)
	}{{
		name:                 "valid_udp_msg",
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
		name:                 "valid_tcp_msg",
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
		// This test checks that we remove unsupported EDNS0 options from
		// the response.
		name:                 "udp_edns0_supported_options",
		network:              dnsserver.NetworkUDP,
		expectedRecordsCount: 1,
		expectedRCode:        dns.RcodeSuccess,
		expectedMsg: func(t *testing.T, m *dns.Msg) {
			opt := m.IsEdns0()
			require.NotNil(t, opt)
			require.Len(t, opt.Option, 1)
			require.Equal(t, uint16(dns.EDNS0TCPKEEPALIVE), opt.Option[0].Option())
		},
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			Extra: []dns.RR{
				&dns.OPT{
					Hdr: dns.RR_Header{
						Name:   ".",
						Rrtype: dns.TypeOPT,
						Class:  2000,
					},
					Option: []dns.EDNS0{
						&dns.EDNS0_TCP_KEEPALIVE{
							Code:    dns.EDNS0COOKIE,
							Timeout: 1,
							Length:  1,
						},
						// The test checks that this option will be removed
						// from the response
						&dns.EDNS0_LOCAL{
							Code: dns.EDNS0LOCALSTART,
							Data: []byte{1, 2, 3},
						},
					},
				},
			},
		},
	}, {
		// Check that we reject invalid DNS messages (like having two questions)
		name:                 "reject_msg",
		network:              dnsserver.NetworkUDP,
		expectedRecordsCount: 0,
		expectedRCode:        dns.RcodeFormatError,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
	}, {
		// Checks that we handle mixed case domain names
		name:                 "udp_mixed_case",
		network:              dnsserver.NetworkUDP,
		expectedRecordsCount: 1,
		expectedRCode:        dns.RcodeSuccess,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "eXaMplE.oRg.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
	}, {
		// Checks that we respond with NotImplemented to requests with OpcodeStatus
		// also checks that Opcode is unchanged in the response
		name:                 "not_implemented_msg",
		network:              dnsserver.NetworkUDP,
		expectedRecordsCount: 0,
		expectedRCode:        dns.RcodeNotImplemented,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true, Opcode: dns.OpcodeStatus},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
	}, {
		// Checks that we respond with SERVFAIL in case if the handler
		// returns an error
		name:                 "handler_failure",
		network:              dnsserver.NetworkUDP,
		expectedRecordsCount: 0,
		expectedRCode:        dns.RcodeServerFailure,
		handler: dnsserver.HandlerFunc(func(
			_ context.Context,
			_ dnsserver.ResponseWriter,
			_ *dns.Msg,
		) (err error) {
			return errors.Error("something went wrong")
		}),
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
	}, {
		// Checks that Z flag is set to zero even when the query has it
		// See https://github.com/miekg/dns/issues/975
		name:                 "msg_with_zflag",
		network:              dnsserver.NetworkUDP,
		expectedRecordsCount: 1,
		expectedRCode:        dns.RcodeSuccess,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true, Zero: true},
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
		handler:              dnsservertest.CreateTestHandler(64),
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
		handler:              dnsservertest.CreateTestHandler(64),
		expectedRecordsCount: 64,
		expectedRCode:        dns.RcodeSuccess,
		expectedTruncated:    false,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			Extra: []dns.RR{
				&dns.OPT{
					Hdr: dns.RR_Header{
						Name:   ".",
						Rrtype: dns.TypeOPT,
						Class:  2000, // Set maximum UDPSize here
					},
				},
			},
		},
	}, {
		// Checks that large responses are NOT truncated when
		// sent over UDP
		name:    "tcp_no_truncate_response",
		network: dnsserver.NetworkTCP,
		// Set a handler that generates a large response
		handler: dnsservertest.CreateTestHandler(64),
		// No truncate
		expectedRecordsCount: 64,
		expectedRCode:        dns.RcodeSuccess,
		expectedTruncated:    false,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := dnsservertest.DefaultHandler()
			if tc.handler != nil {
				handler = tc.handler
			}
			_, addr := dnsservertest.RunDNSServer(t, handler)

			// Send this test message to our server over UDP
			c := new(dns.Client)
			c.Net = string(tc.network)
			c.UDPSize = 7000 // need to be set to read large responses

			res, _, err := c.Exchange(tc.req, addr)
			require.NoError(t, err)
			require.NotNil(t, res)
			if tc.expectedMsg != nil {
				tc.expectedMsg(t, res)
			}

			dnsservertest.RequireResponse(t, tc.req, res, tc.expectedRecordsCount, tc.expectedRCode, tc.expectedTruncated)
		})
	}
}

func TestServerDNS_integration_tcpQueriesPipelining(t *testing.T) {
	// As per RFC 7766 we should support queries pipelining for TCP, that is we
	// should be able to process incoming queries in parallel and write
	// responses out of order.
	_, addr := dnsservertest.RunDNSServer(t, dnsservertest.DefaultHandler())

	// First - establish a connection
	conn, err := net.Dial("tcp", addr)
	require.Nil(t, err)

	defer log.OnCloserError(conn, log.DEBUG)

	// Second - write multiple queries (let's say 100) and save
	// those queries IDs
	count := 100
	ids := map[uint16]bool{}
	for i := 0; i < count; i++ {
		req := new(dns.Msg)
		req.Id = uint16(i)
		req.RecursionDesired = true
		name := "example.org."
		req.Question = []dns.Question{
			{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		}

		// Save the ID
		ids[req.Id] = true

		// Pack the message
		b, _ := req.Pack()
		msg := make([]byte, 2+len(b))
		binary.BigEndian.PutUint16(msg, uint16(len(b)))
		copy(msg[2:], b)

		// Write it to the connection
		_, _ = conn.Write(msg)
	}

	// Now read the responses and check their IDs
	for i := 0; i < count; i++ {
		_ = conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
		l := make([]byte, 2)
		_, err = conn.Read(l)
		require.NoError(t, err)

		packetLen := binary.BigEndian.Uint16(l)
		buf := make([]byte, packetLen)
		_, err = io.ReadFull(conn, buf)
		require.NoError(t, err)

		// Unpack the message
		res := &dns.Msg{}
		err = res.Unpack(buf)
		require.NoError(t, err)

		// Check some general response properties
		require.True(t, res.Response)
		require.Equal(t, dns.RcodeSuccess, res.Rcode)

		// Now check the response ID
		v, ok := ids[res.Id]
		require.True(t, v)
		require.True(t, ok)

		// Remove it from the map since it was already received
		delete(ids, res.Id)
	}
}

func TestServerDNS_integration_udpMsgIgnore(t *testing.T) {
	_, addr := dnsservertest.RunDNSServer(t, dnsservertest.DefaultHandler())
	conn, err := net.Dial("udp", addr)
	require.Nil(t, err)

	defer log.OnCloserError(conn, log.DEBUG)

	// Write some crap
	_, err = conn.Write([]byte{1, 3, 1, 52, 12, 5, 32, 12})
	require.NoError(t, err)

	// Try reading the response and make sure that it times out
	_ = conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
	buf := make([]byte, 500)
	n, err := conn.Read(buf)

	require.Error(t, err)
	require.Equal(t, 0, n)
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	require.True(t, netErr.Timeout())

	// Check that the server is capable of processing messages after it

	// Create a test message
	req := new(dns.Msg)
	req.Id = dns.Id()
	req.RecursionDesired = true
	name := "example.org."
	req.Question = []dns.Question{
		{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	// Send this test message to our server over UDP
	c := new(dns.Client)
	c.Net = "udp"
	res, _, err := c.Exchange(req, addr)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.True(t, res.Response)
}

func TestServerDNS_integration_tcpMsgIgnore(t *testing.T) {
	testCases := []struct {
		name          string
		buf           []byte
		timeout       time.Duration
		expectedError func(err error)
	}{
		{
			name: "invalid_input_timeout",
			// First test: write some crap with 2-bytes "length" larger than
			// the data actually sent. Check that it times out if the timeout
			// is small.
			buf:     []byte{1, 3, 1, 52, 12, 5, 32, 12},
			timeout: time.Millisecond * 100,
			expectedError: func(err error) {
				var netErr net.Error
				require.ErrorAs(t, err, &netErr)
				require.True(t, netErr.Timeout())
			},
		},
		{
			name: "invalid_input_closed_after_timeout",
			// Check that the TCP connection will be closed if it cannot
			// read the full DNS query
			buf:     []byte{1, 3, 1, 52, 12, 5, 32, 12},
			timeout: dnsserver.DefaultTCPIdleTimeout * 2,
			expectedError: func(err error) {
				require.Equal(t, io.EOF, err)
			},
		},
		{
			name: "invalid_input_closed_immediately",
			// Packet length is short so we can quickly detect that
			// this is a crap message, check that the connection is closed
			// immediately
			buf:     []byte{0, 1, 1, 52, 12, 5, 32, 12},
			timeout: dnsserver.DefaultTCPIdleTimeout / 2,
			expectedError: func(err error) {
				var netErr net.Error
				if errors.As(err, &netErr) {
					require.False(t, netErr.Timeout())
				} else {
					require.Equal(t, io.EOF, err)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, addr := dnsservertest.RunDNSServer(t, dnsservertest.DefaultHandler())
			conn, err := net.Dial("tcp", addr)
			require.Nil(t, err)

			defer log.OnCloserError(conn, log.DEBUG)

			// Write the invalid request
			_, err = conn.Write(tc.buf)
			require.NoError(t, err)

			// Try reading the response and make sure that it times out
			_ = conn.SetReadDeadline(time.Now().Add(tc.timeout))
			buf := make([]byte, 500)
			n, err := conn.Read(buf)
			require.Error(t, err)
			require.Equal(t, 0, n)
			tc.expectedError(err)
		})
	}
}
