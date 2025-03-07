package dnsserver_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerDNS_StartShutdown(t *testing.T) {
	_, _ = dnsservertest.RunDNSServer(t, dnsservertest.NewDefaultHandler())
}

func TestServerDNS_integration_query(t *testing.T) {
	testCases := []struct {
		handler          dnsserver.Handler
		req              *dns.Msg
		wantMsg          func(t *testing.T, m *dns.Msg)
		name             string
		network          dnsserver.Network
		wantRecordsCount int
		wantRCode        int
		wantTruncated    bool
	}{{
		name:    "valid_udp_msg",
		network: dnsserver.NetworkUDP,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
		handler:          dnsservertest.NewDefaultHandler(),
		wantRecordsCount: 1,
		wantRCode:        dns.RcodeSuccess,
	}, {
		name:    "valid_tcp_msg",
		network: dnsserver.NetworkTCP,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
		handler:          dnsservertest.NewDefaultHandler(),
		wantRecordsCount: 1,
		wantRCode:        dns.RcodeSuccess,
	}, {
		// This test checks that we remove unsupported EDNS0 options from
		// the response.
		name:    "udp_edns0_supported_options",
		network: dnsserver.NetworkUDP,
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
						&dns.EDNS0_EXPIRE{
							Code:   dns.EDNS0EXPIRE,
							Expire: 1,
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
		handler: dnsservertest.NewDefaultHandler(),
		wantMsg: func(t *testing.T, m *dns.Msg) {
			opt := m.IsEdns0()
			require.NotNil(t, opt)
			require.Len(t, opt.Option, 1)
			require.Equal(t, uint16(dns.EDNS0EXPIRE), opt.Option[0].Option())
		},
		wantRecordsCount: 1,
		wantRCode:        dns.RcodeSuccess,
	}, {
		// Check that we reject invalid DNS messages (like having two questions)
		name:    "reject_msg",
		network: dnsserver.NetworkUDP,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
		handler:          dnsservertest.NewDefaultHandler(),
		wantRecordsCount: 0,
		wantRCode:        dns.RcodeFormatError,
	}, {
		// Check that we handle mixed case domain names.
		name:    "udp_mixed_case",
		network: dnsserver.NetworkUDP,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "eXaMplE.oRg.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
		handler:          dnsservertest.NewDefaultHandler(),
		wantRecordsCount: 1,
		wantRCode:        dns.RcodeSuccess,
	}, {
		// Checks that we respond with NotImplemented to requests with OpcodeStatus
		// also checks that Opcode is unchanged in the response
		name:    "not_implemented_msg",
		network: dnsserver.NetworkUDP,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true, Opcode: dns.OpcodeStatus},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
		handler:          dnsservertest.NewDefaultHandler(),
		wantRecordsCount: 0,
		wantRCode:        dns.RcodeNotImplemented,
	}, {
		// Checks that we respond with SERVFAIL in case if the handler
		// returns an error
		name:    "handler_failure",
		network: dnsserver.NetworkUDP,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
		handler: dnsserver.HandlerFunc(func(
			_ context.Context,
			_ dnsserver.ResponseWriter,
			_ *dns.Msg,
		) (err error) {
			return errors.Error("something went wrong")
		}),
		wantRecordsCount: 0,
		wantRCode:        dns.RcodeServerFailure,
	}, {
		// Checks that Z flag is set to zero even when the query has it
		// See https://github.com/miekg/dns/issues/975
		name:    "msg_with_zflag",
		network: dnsserver.NetworkUDP,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true, Zero: true},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
		handler:          dnsservertest.NewDefaultHandler(),
		wantRecordsCount: 1,
		wantRCode:        dns.RcodeSuccess,
	}, {
		// Checks that large responses are getting truncated when
		// sent over UDP
		name:    "udp_truncate_response",
		network: dnsserver.NetworkUDP,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
		// Set a handler that generates a large response
		handler:          dnsservertest.NewDefaultHandlerWithCount(64),
		wantRecordsCount: 0,
		wantRCode:        dns.RcodeSuccess,
		wantTruncated:    true,
	}, {
		// Checks that if UDP size is large enough there would be no
		// truncated responses
		name:    "udp_edns0_no_truncate",
		network: dnsserver.NetworkUDP,
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
		// Set a handler that generates a large response
		handler:          dnsservertest.NewDefaultHandlerWithCount(64),
		wantRecordsCount: 64,
		wantRCode:        dns.RcodeSuccess,
		wantTruncated:    false,
	}, {
		// Checks that large responses are NOT truncated when
		// sent over UDP
		name:    "tcp_no_truncate_response",
		network: dnsserver.NetworkTCP,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
		// Set a handler that generates a large response
		handler: dnsservertest.NewDefaultHandlerWithCount(64),
		// No truncate
		wantRecordsCount: 64,
		wantRCode:        dns.RcodeSuccess,
		wantTruncated:    false,
	}, {
		// Check that the server adds keep alive option when the client
		// indicates that supports it.
		name:    "tcp_edns0_tcp_keep-alive",
		network: dnsserver.NetworkTCP,
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
					Option: []dns.EDNS0{
						&dns.EDNS0_TCP_KEEPALIVE{
							Code:    dns.EDNS0TCPKEEPALIVE,
							Timeout: 100,
						},
					},
				},
			},
		},
		handler:          dnsservertest.NewDefaultHandler(),
		wantRecordsCount: 1,
		wantRCode:        dns.RcodeSuccess,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, addr := dnsservertest.RunDNSServer(t, tc.handler)

			// Send this test message to our server over UDP
			c := new(dns.Client)
			c.Net = string(tc.network)
			c.UDPSize = 7000 // need to be set to read large responses

			resp, _, err := c.Exchange(tc.req, addr)
			require.NoError(t, err)
			require.NotNil(t, resp)
			if tc.wantMsg != nil {
				tc.wantMsg(t, resp)
			}

			dnsservertest.RequireResponse(
				t,
				tc.req,
				resp,
				tc.wantRecordsCount,
				tc.wantRCode,
				tc.wantTruncated,
			)

			reqKeepAliveOpt := dnsservertest.FindEDNS0Option[*dns.EDNS0_TCP_KEEPALIVE](tc.req)
			respKeepAliveOpt := dnsservertest.FindEDNS0Option[*dns.EDNS0_TCP_KEEPALIVE](resp)
			if tc.network == dnsserver.NetworkTCP && reqKeepAliveOpt != nil {
				require.NotNil(t, respKeepAliveOpt)
				expectedTimeout := uint16(dnsserver.DefaultTCPIdleTimeout.Milliseconds() / 100)
				require.Equal(t, expectedTimeout, respKeepAliveOpt.Timeout)
			} else {
				require.Nil(t, respKeepAliveOpt)
			}
		})
	}
}

func TestServerDNS_integration_tcpQueriesPipelining(t *testing.T) {
	// As per RFC 7766 we should support queries pipelining for TCP, that is
	// server must be able to process incoming queries in parallel and write
	// responses possibly out of order within the same connection.
	_, addr := dnsservertest.RunDNSServer(t, dnsservertest.NewDefaultHandler())

	// Establish a connection.
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, conn.Close)

	// Write multiple queries and save their IDs.
	const queriesNum = 100

	sentIDs := make(map[uint16]string, queriesNum)
	for i := range queriesNum {
		name := fmt.Sprintf("host%d.org", i)
		req := dnsservertest.CreateMessage(name, dns.TypeA)
		req.Id = uint16(i + 1)

		// Pack the message.
		var b []byte
		b, err = req.Pack()
		require.NoError(t, err)

		msg := make([]byte, 2+len(b))
		binary.BigEndian.PutUint16(msg, uint16(len(b)))
		copy(msg[2:], b)

		// Write it to the connection.
		var n int
		n, err = conn.Write(msg)
		require.NoError(t, err)
		require.Equal(t, len(msg), n)

		// Save the ID.
		sentIDs[req.Id] = dns.Fqdn(name)
	}

	// Read the responses and check their IDs.
	receivedIDs := make(map[uint16]string, queriesNum)
	for range queriesNum {
		err = conn.SetReadDeadline(time.Now().Add(time.Second))
		require.NoError(t, err)

		// Read the length of the message.
		var length uint16
		err = binary.Read(conn, binary.BigEndian, &length)
		require.NoError(t, err)

		// Read the message.
		buf := make([]byte, length)
		_, err = io.ReadFull(conn, buf)
		require.NoError(t, err)

		// Unpack the message.
		res := &dns.Msg{}
		err = res.Unpack(buf)
		require.NoError(t, err)

		// Check some general response properties.
		require.True(t, res.Response)
		require.Equal(t, dns.RcodeSuccess, res.Rcode)

		require.NotEmpty(t, res.Question)
		receivedIDs[res.Id] = res.Question[0].Name
	}

	assert.Equal(t, sentIDs, receivedIDs)
}

func TestServerDNS_integration_udpMsgIgnore(t *testing.T) {
	_, addr := dnsservertest.RunDNSServer(t, dnsservertest.NewDefaultHandler())
	conn, err := net.Dial("udp", addr)
	require.Nil(t, err)

	testutil.CleanupAndRequireSuccess(t, conn.Close)

	// Write some crap
	_, err = conn.Write([]byte{1, 3, 1, 52, 12, 5, 32, 12})
	require.NoError(t, err)

	// Try reading the response and make sure that it times out
	err = conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
	require.NoError(t, err)

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
	t.Parallel()

	testCases := []struct {
		expectedError func(err error)
		name          string
		buf           []byte
		timeout       time.Duration
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
			t.Parallel()

			_, addr := dnsservertest.RunDNSServer(t, dnsservertest.NewDefaultHandler())
			conn, err := net.Dial("tcp", addr)
			require.Nil(t, err)

			testutil.CleanupAndRequireSuccess(t, conn.Close)

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
