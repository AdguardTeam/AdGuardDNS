package dnsserver_test

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestServerTLS_integration_queryTLS(t *testing.T) {
	tlsConfig := dnsservertest.CreateServerTLSConfig("example.org")
	addr := dnsservertest.RunTLSServer(t, dnsservertest.DefaultHandler(), tlsConfig)

	// Create a test message.
	req := new(dns.Msg)
	req.Id = dns.Id()
	req.RecursionDesired = true
	name := "example.org."
	req.Question = []dns.Question{
		{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	// Send this test message to our server over TCP.
	c := new(dns.Client)
	c.TLSConfig = tlsConfig
	c.Net = "tcp-tls"
	resp, _, err := c.Exchange(req, addr.String())
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.True(t, resp.Response)
	require.False(t, resp.Truncated)

	// EDNS0 padding is only present when request also has padding opt.
	paddingOpt := dnsservertest.FindEDNS0Option[*dns.EDNS0_PADDING](resp)
	require.Nil(t, paddingOpt)
}

func TestServerTLS_integration_msgIgnore(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		buf           []byte
		timeout       time.Duration
		expectedError func(t *testing.T, err error)
	}{
		{
			name: "invalid_input_timeout",
			// First test: write some crap with 2-bytes "length" larger than
			// the data actually sent. Check that it times out if the timeout
			// is small.
			buf:     []byte{1, 3, 1, 52, 12, 5, 32, 12},
			timeout: time.Millisecond * 100,
			expectedError: func(t *testing.T, err error) {
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
			timeout: dnsserver.DefaultReadTimeout * 2,
			expectedError: func(t *testing.T, err error) {
				require.Equal(t, io.EOF, err)
			},
		},
		{
			name: "invalid_input_closed_immediately",
			// Packet length is short so we can quickly detect that
			// this is a crap message, check that the connection is closed
			// immediately
			buf:     []byte{0, 1, 1, 52, 12, 5, 32, 12},
			timeout: time.Millisecond * 100,
			expectedError: func(t *testing.T, err error) {
				require.Equal(t, io.EOF, err)
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tlsConfig := dnsservertest.CreateServerTLSConfig("example.org")
			h := dnsservertest.DefaultHandler()
			addr := dnsservertest.RunTLSServer(t, h, tlsConfig)

			conn, err := tls.Dial("tcp", addr.String(), tlsConfig)
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
			tc.expectedError(t, err)
		})
	}
}

func TestServerTLS_integration_noTruncateQuery(t *testing.T) {
	// Handler that writes a huge response which would not fit
	// into a UDP response, but it should fit a TCP response just okay.
	handler := dnsservertest.CreateTestHandler(64)

	tlsConfig := dnsservertest.CreateServerTLSConfig("example.org")
	addr := dnsservertest.RunTLSServer(t, handler, tlsConfig)

	// Create a test message
	req := new(dns.Msg)
	req.Id = dns.Id()
	req.RecursionDesired = true
	name := "example.org."
	req.Question = []dns.Question{
		{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	// Send this test message to our server over TCP
	c := new(dns.Client)
	c.TLSConfig = tlsConfig
	c.Net = "tcp-tls"
	resp, _, err := c.Exchange(req, addr.String())
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.True(t, resp.Response)
	require.False(t, resp.Truncated)

	// EDNS0 padding is only present when request also has padding opt.
	paddingOpt := dnsservertest.FindEDNS0Option[*dns.EDNS0_PADDING](resp)
	require.Nil(t, paddingOpt)
}

func TestServerTLS_integration_queriesPipelining(t *testing.T) {
	// Just like a TCP server case, we should support queries pipelining
	// i.e. we should be able to process incoming queries in parallel and
	// write responses out of order.
	tlsConfig := dnsservertest.CreateServerTLSConfig("example.org")
	addr := dnsservertest.RunTLSServer(t, dnsservertest.DefaultHandler(), tlsConfig)

	// First - establish a connection
	conn, err := tls.Dial("tcp", addr.String(), tlsConfig)
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

func TestServerTLS_integration_ENDS0Padding(t *testing.T) {
	tlsConfig := dnsservertest.CreateServerTLSConfig("example.org")
	addr := dnsservertest.RunTLSServer(t, dnsservertest.DefaultHandler(), tlsConfig)

	req := dnsservertest.CreateMessage("example.org.", dns.TypeA)
	req.Extra = []dns.RR{dnsservertest.NewEDNS0Padding(req.Len(), dns.DefaultMsgSize)}

	// Send test message to our server over TCP
	c := &dns.Client{Net: "tcp-tls", TLSConfig: tlsConfig}
	resp, _, err := c.Exchange(req, addr.String())
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.True(t, resp.Response)
	require.False(t, resp.Truncated)

	paddingOpt := dnsservertest.FindEDNS0Option[*dns.EDNS0_PADDING](resp)
	require.NotNil(t, paddingOpt)
	require.NotEmpty(t, paddingOpt.Padding)
}
