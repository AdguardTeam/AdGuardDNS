package dnsserver_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
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

// testHdrBits is a valid header's bits field:
//   - QR=0
//   - opcode=0
//   - AA=0
//   - TC=0
//   - RD=1
//   - RA=0
//   - Z=0
//   - RCODE=0
const testHdrBits = 0x0100

// rootQuestion is a DNS question of type A and class INET for the root domain.
var rootQuestion = slices.Concat(
	[]byte{0x00},
	binary.BigEndian.AppendUint16(nil, dns.TypeA),
	binary.BigEndian.AppendUint16(nil, dns.ClassINET),
)

// unit is a convenience alias for an empty struct.
type unit = struct{}

// newTestHdr returns a DNS header as a byte slice.
func newTestHdr(tb testing.TB, hdr dns.Header) (hdrData []byte) {
	tb.Helper()

	hdrData = binary.BigEndian.AppendUint16(hdrData, hdr.Id)
	hdrData = binary.BigEndian.AppendUint16(hdrData, hdr.Bits)
	hdrData = binary.BigEndian.AppendUint16(hdrData, hdr.Qdcount)
	hdrData = binary.BigEndian.AppendUint16(hdrData, hdr.Ancount)
	hdrData = binary.BigEndian.AppendUint16(hdrData, hdr.Nscount)
	hdrData = binary.BigEndian.AppendUint16(hdrData, hdr.Arcount)

	return hdrData
}

// newInvalidMsgMetrics returns a metrics listener that signals when an invalid
// message is received and a channel to receive the signal.
func newInvalidMsgMetrics(tb testing.TB) (mtrc dnsserver.MetricsListener, ch chan unit) {
	tb.Helper()

	ch = make(chan unit)

	m := dnsservertest.NewMetricsListener()
	m.OnOnInvalidMsg = func(ctx context.Context) {
		// TODO(e.burkov):  Use [testutil.NewPanicT].
		testutil.RequireSend(testutil.PanicT{}, ch, unit{}, testTimeout)
	}

	return m, ch
}

func TestServerDNS_StartShutdown(t *testing.T) {
	_, _ = dnsservertest.RunDNSServer(t, nil)
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
		req: dnsservertest.NewReq(
			dnsservertest.DomainName,
			dns.TypeA,
			dns.ClassINET,
		),
		handler:          dnsservertest.NewDefaultHandler(),
		wantRecordsCount: 1,
		wantRCode:        dns.RcodeSuccess,
	}, {
		name:    "valid_tcp_msg",
		network: dnsserver.NetworkTCP,
		req: dnsservertest.NewReq(
			dnsservertest.DomainName,
			dns.TypeA,
			dns.ClassINET,
		),
		handler:          dnsservertest.NewDefaultHandler(),
		wantRecordsCount: 1,
		wantRCode:        dns.RcodeSuccess,
	}, {
		// This test checks that we remove unsupported EDNS0 options from
		// the response.
		name:    "udp_edns0_supported_options",
		network: dnsserver.NetworkUDP,
		req: dnsservertest.NewReq(
			dnsservertest.DomainName,
			dns.TypeA,
			dns.ClassINET,
			dnsservertest.SectionExtra{dnsservertest.NewOPT(
				false,
				2000,
				&dns.EDNS0_EXPIRE{Code: dns.EDNS0EXPIRE, Expire: 1},
				&dns.EDNS0_LOCAL{Code: dns.EDNS0LOCALSTART, Data: []byte{1, 2, 3}},
			)},
		),
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
			MsgHdr: dns.MsgHdr{
				Id:               dns.Id(),
				RecursionDesired: true,
			},
			Question: []dns.Question{{
				Name:   dnsservertest.FQDN,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}, {
				Name:   dnsservertest.FQDN,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		},
		handler:          dnsservertest.NewDefaultHandler(),
		wantRecordsCount: 0,
		wantRCode:        dns.RcodeFormatError,
	}, {
		// Check that we handle mixed case domain names.
		name:    "udp_mixed_case",
		network: dnsserver.NetworkUDP,
		req: dnsservertest.NewReq(
			"tEsT.eXaMplE",
			dns.TypeA,
			dns.ClassINET,
		),
		handler:          dnsservertest.NewDefaultHandler(),
		wantRecordsCount: 1,
		wantRCode:        dns.RcodeSuccess,
	}, {
		// Check that responses to requests with [dns.OpcodeStatus] are
		// [dns.RcodeNotImplemented] and also check that Opcode is unchanged in
		// the response.
		name:    "not_implemented_msg",
		network: dnsserver.NetworkUDP,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:               dns.Id(),
				RecursionDesired: true,
				Opcode:           dns.OpcodeStatus,
			},
			Question: []dns.Question{{
				Name:   dnsservertest.FQDN,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		},
		handler:          dnsservertest.NewDefaultHandler(),
		wantRecordsCount: 0,
		wantRCode:        dns.RcodeNotImplemented,
	}, {
		// Checks that we respond with SERVFAIL in case if the handler
		// returns an error
		name:    "handler_failure",
		network: dnsserver.NetworkUDP,
		req: dnsservertest.NewReq(
			dnsservertest.DomainName,
			dns.TypeA,
			dns.ClassINET,
		),
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
		// Check that Z flag is set to zero even when the query has it.  See
		// https://github.com/miekg/dns/issues/975.
		name:    "msg_with_zflag",
		network: dnsserver.NetworkUDP,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:               dns.Id(),
				RecursionDesired: true,
				Zero:             true,
			},
			Question: []dns.Question{{
				Name:   dnsservertest.FQDN,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		},
		handler:          dnsservertest.NewDefaultHandler(),
		wantRecordsCount: 1,
		wantRCode:        dns.RcodeSuccess,
	}, {
		// Check that large responses are getting truncated when sent over UDP.
		name:    "udp_truncate_response",
		network: dnsserver.NetworkUDP,
		req: &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
			Question: []dns.Question{
				{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
		// Set a handler that generates a large response.
		handler:          dnsservertest.NewDefaultHandlerWithCount(64),
		wantRecordsCount: 0,
		wantRCode:        dns.RcodeSuccess,
		wantTruncated:    true,
	}, {
		// Check that if UDP size is large enough there would be no truncated
		// responses.
		name:    "udp_edns0_no_truncate",
		network: dnsserver.NetworkUDP,
		req: dnsservertest.NewReq(
			dnsservertest.DomainName,
			dns.TypeA,
			dns.ClassINET,
			dnsservertest.SectionExtra{dnsservertest.NewOPT(false, 2000)},
		),
		// Set a handler that generates a large response.
		handler:          dnsservertest.NewDefaultHandlerWithCount(64),
		wantRecordsCount: 64,
		wantRCode:        dns.RcodeSuccess,
		wantTruncated:    false,
	}, {
		// Checks that large responses are NOT truncated when sent over UDP.
		name:    "tcp_no_truncate_response",
		network: dnsserver.NetworkTCP,
		req: dnsservertest.NewReq(
			dnsservertest.DomainName,
			dns.TypeA,
			dns.ClassINET,
		),
		// Set a handler that generates a large response.
		handler: dnsservertest.NewDefaultHandlerWithCount(64),
		// No truncate.
		wantRecordsCount: 64,
		wantRCode:        dns.RcodeSuccess,
		wantTruncated:    false,
	}, {
		// Check that the server adds keep alive option when the client
		// indicates that supports it.
		name:    "tcp_edns0_tcp_keep-alive",
		network: dnsserver.NetworkTCP,
		req: dnsservertest.NewReq(
			dnsservertest.DomainName,
			dns.TypeA,
			dns.ClassINET,
			dnsservertest.SectionExtra{dnsservertest.NewOPT(false, 2000, &dns.EDNS0_TCP_KEEPALIVE{
				Code:    dns.EDNS0TCPKEEPALIVE,
				Timeout: 100,
			})},
		),
		handler:          dnsservertest.NewDefaultHandler(),
		wantRecordsCount: 1,
		wantRCode:        dns.RcodeSuccess,
	}}

	for _, tc := range testCases {
		conf := &dnsserver.ConfigDNS{
			Base: &dnsserver.ConfigBase{
				Handler: tc.handler,
			},
			MaxUDPRespSize: dns.MaxMsgSize,
		}

		c := &dns.Client{
			Net: string(tc.network),
			// Need to be set to read large responses.
			UDPSize: 7000,
		}

		t.Run(tc.name, func(t *testing.T) {
			_, addr := dnsservertest.RunDNSServer(t, conf)

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
	_, addr := dnsservertest.RunDNSServer(t, nil)

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
	_, addr := dnsservertest.RunDNSServer(t, nil)
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
		wantErr require.ErrorAssertionFunc
		name    string
		buf     []byte
		timeout time.Duration
	}{{
		name: "invalid_input_timeout",
		// First test: write some crap with 2-bytes "length" larger than
		// the data actually sent. Check that it times out if the timeout
		// is small.
		buf:     []byte{1, 3, 1, 52, 12, 5, 32, 12},
		timeout: time.Millisecond * 100,
		wantErr: func(t require.TestingT, err error, _ ...any) {
			var netErr net.Error
			require.ErrorAs(t, err, &netErr)
			require.True(t, netErr.Timeout())
		},
	}, {
		name: "invalid_input_closed_after_timeout",
		// Check that the TCP connection will be closed if it cannot
		// read the full DNS query
		buf:     []byte{1, 3, 1, 52, 12, 5, 32, 12},
		timeout: dnsserver.DefaultTCPIdleTimeout * 2,
		wantErr: func(t require.TestingT, err error, _ ...any) {
			require.Equal(t, io.EOF, err)
		},
	}, {
		name: "invalid_input_closed_immediately",
		// Packet length is short so we can quickly detect that
		// this is a crap message, check that the connection is closed
		// immediately
		buf:     []byte{0, 1, 1, 52, 12, 5, 32, 12},
		timeout: dnsserver.DefaultTCPIdleTimeout / 2,
		wantErr: func(t require.TestingT, err error, _ ...any) {
			var netErr net.Error
			if errors.As(err, &netErr) {
				require.False(t, netErr.Timeout())
			} else {
				require.Equal(t, io.EOF, err)
			}
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, addr := dnsservertest.RunDNSServer(t, nil)
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
			tc.wantErr(t, err)
		})
	}
}

func TestServerDNS_ServeTCP_badHeader(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		data []byte
	}{{
		// Obviously invalid packet.
		name: "bad_packet",
		data: []byte{0x00, 0x00, 0x00, 0x00},
	}, {
		// QDCOUNT=32768 (0x8000, testing signed/unsigned handling).
		name: "qdcount_32768",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 0x8000}),
			rootQuestion,
		),
	}, {
		// QDCOUNT=1000 forcing parser to allocate structures.
		name: "qdcount_1000",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1000}),
			rootQuestion,
		),
	}, {
		// QDCOUNT=19 forcing parser to allocate structures.
		name: "qdcount_19",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 19}),
			bytes.Repeat(rootQuestion, 1),
		),
	}, {
		// QDCOUNT=65535 with 1 question.
		name: "qdcount_max",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 0xFFFF}),
			rootQuestion,
		),
	}, {
		// QDCOUNT=65535 and ANCOUNT=65535 (impossible combination).
		name: "qdcount_max_ancount_max",
		data: slices.Concat(
			newTestHdr(t, dns.Header{
				Id:      dns.Id(),
				Bits:    testHdrBits,
				Qdcount: 0xFFFF,
				Ancount: 0xFFFF,
			}),
			rootQuestion,
		),
	}, {
		// QDCOUNT=5 but 3 actual questions.
		name: "qdcount_5_actual_3",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 5}),
			bytes.Repeat(rootQuestion, 3),
		),
	}, {
		// QDCOUNT=5 but 1 actual question.
		name: "qdcount_5_actual_1",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 5}),
			bytes.Repeat(rootQuestion, 1),
		),
	}}

	for _, tc := range testCases {
		conf := &dnsserver.ConfigDNS{
			Base: &dnsserver.ConfigBase{Handler: dnsservertest.NewPanicHandler()},
		}

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var invalidMsgCh chan unit
			conf.Base.Metrics, invalidMsgCh = newInvalidMsgMetrics(t)

			_, addr := dnsservertest.RunDNSServer(t, conf)

			conn, err := net.Dial("tcp", addr)
			require.NoError(t, err)
			testutil.CleanupAndRequireSuccess(t, conn.Close)

			deadline := time.Now().Add(testTimeout)
			require.NoError(t, conn.SetDeadline(deadline))

			err = binary.Write(conn, binary.BigEndian, uint16(len(tc.data)))
			require.NoError(t, err)

			n, err := conn.Write(tc.data)
			require.NoError(t, err)
			require.Equal(t, len(tc.data), n)

			_, ok := testutil.RequireReceive(t, invalidMsgCh, testTimeout)
			require.True(t, ok)
		})
	}
}

func TestServerDNS_ServeTCP_badQuestion(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		data []byte
	}{{
		// QNAME with label length exactly 64 (invalid, byte 0x40 has
		// reserved top bits).
		name: "qname_label_length_64",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1}),
			[]byte{64},
			make([]byte, 64),
			rootQuestion,
		),
	}, {
		// QNAME with label length 81 (invalid, byte 0x51 has reserved
		// top bits).
		name: "qname_label_length_81",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1}),
			[]byte{81},
			bytes.Repeat([]byte{'q'}, 81),
			rootQuestion,
		),
	}, {
		// QNAME total length exceeds 255 octets (5 labels of 63 bytes each
		// = 5*64+1 = 321).
		name: "qname_total_length_overflow",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1}),
			bytes.Repeat(
				// 1 byte of length + 63 bytes of data.
				append([]byte{63}, bytes.Repeat([]byte{0}, 63)...),
				5,
			),
			rootQuestion,
		),
	}, {
		// QNAME with 128 labels (total > 255 octets).
		name: "qname_128_labels",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1}),
			bytes.Repeat([]byte{0x01, 'a'}, 128),
			rootQuestion,
		),
	}, {
		// QNAME with 64-character TLD (exceeds label max of 63).
		name: "qname_64char_tld",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1}),
			append([]byte{4}, "test"...),
			append([]byte{64}, make([]byte, 64)...),
			rootQuestion,
		),
	}, {
		// QNAME label with invalid length byte 0x42 (reserved top bits).
		name: "qname_label_length_0x42",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1}),
			[]byte{0x42},
			bytes.Repeat([]byte{'x'}, 0x42),
			rootQuestion,
		),
	}, {
		// QNAME with 255 labels (extreme case, total > 255 octets).
		name: "qname_255_labels",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1}),
			bytes.Repeat([]byte{0x01, 'a'}, 255),
			rootQuestion,
		),
	}}

	for _, tc := range testCases {
		conf := &dnsserver.ConfigDNS{
			Base: &dnsserver.ConfigBase{Handler: dnsservertest.NewPanicHandler()},
		}

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var invalidMsgCh chan unit
			conf.Base.Metrics, invalidMsgCh = newInvalidMsgMetrics(t)

			_, addr := dnsservertest.RunDNSServer(t, conf)

			conn, err := net.Dial("tcp", addr)
			require.NoError(t, err)
			testutil.CleanupAndRequireSuccess(t, conn.Close)

			deadline := time.Now().Add(testTimeout)
			require.NoError(t, conn.SetDeadline(deadline))

			err = binary.Write(conn, binary.BigEndian, uint16(len(tc.data)))
			require.NoError(t, err)

			n, err := conn.Write(tc.data)
			require.NoError(t, err)
			require.Equal(t, len(tc.data), n)

			_, ok := testutil.RequireReceive(t, invalidMsgCh, testTimeout)
			require.True(t, ok)
		})
	}
}

func TestServerDNS_ServeTCP_badRR(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		data []byte
	}{{
		// OPT RR with RDLENGTH=65535 but no RDATA follows.
		name: "opt_rdlength_max",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: 0x01, Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR with NAME=root, TYPE=OPT(41), CLASS=4096, TTL=0,
			// RDLENGTH=65535.
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF},
		),
	}, {
		// OPT RR RDLENGTH claims 4000 bytes but only 10 present.
		name: "opt_rdlength_mismatch",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR with RDLENGTH=4000.
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x0F, 0xA0},
			make([]byte, 10),
		),
	}, {
		// OPT RR with NAME containing invalid label length.
		name: "opt_name_invalid_label",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR with NAME containing reserved label length byte 0x40
			// instead of root.
			[]byte{0x40, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		),
	}, {
		// OPT RR with NAME as compression pointer (0xC0FF, pointing to offset
		// 255, past end of message) instead of root.
		name: "opt_name_compression_pointer",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR with NAME=compression pointer, TYPE=OPT(41), CLASS=4096,
			// TTL=0, RDLENGTH=0.
			[]byte{0xC0, 0xFF, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		),
	}}

	for _, tc := range testCases {
		conf := &dnsserver.ConfigDNS{
			Base: &dnsserver.ConfigBase{Handler: dnsservertest.NewPanicHandler()},
		}

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var invalidMsgCh chan unit
			conf.Base.Metrics, invalidMsgCh = newInvalidMsgMetrics(t)

			_, addr := dnsservertest.RunDNSServer(t, conf)

			conn, err := net.Dial("tcp", addr)
			require.NoError(t, err)
			testutil.CleanupAndRequireSuccess(t, conn.Close)

			deadline := time.Now().Add(testTimeout)
			require.NoError(t, conn.SetDeadline(deadline))

			err = binary.Write(conn, binary.BigEndian, uint16(len(tc.data)))
			require.NoError(t, err)

			n, err := conn.Write(tc.data)
			require.NoError(t, err)
			require.Equal(t, len(tc.data), n)

			_, ok := testutil.RequireReceive(t, invalidMsgCh, testTimeout)
			require.True(t, ok)
		})
	}
}

func TestServerDNS_ServeTCP_badEDNS0(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		data []byte
	}{{
		// EDNS option with OPTION-LENGTH extending beyond packet.
		name: "edns_option_length_beyond_packet",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR with RDLENGTH=8 (accurate).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
			// EDNS option: CODE=10, LENGTH=100 (claims 100 bytes), but only 4
			// bytes of data follow.
			[]byte{0x00, 0x0A, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00},
		),
	}, {
		// Multiple EDNS options whose combined length exceeds RDLEN.
		name: "edns_options_exceed_rdlen",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR with RDLENGTH=10.
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A},
			// Option 1: CODE=10, LENGTH=2, DATA=2 bytes (6 bytes).
			[]byte{0x00, 0x0A, 0x00, 0x02, 0x00, 0x00},
			// Option 2: CODE=12, LENGTH=6, but only 0 remain in RDLEN (4 bytes
			// left, need 4+6).
			[]byte{0x00, 0x0C, 0x00, 0x06},
		),
	}, {
		// ECS with IPv4 source prefix length 33 (exceeds 32-bit).
		name: "ecs_ipv4_prefix_33",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=13 (4 option hdr + 9 ECS data).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D},
			// ECS option: CODE=8, LENGTH=9.
			[]byte{0x00, 0x08, 0x00, 0x09},
			// FAMILY=1(IPv4), SOURCE PREFIX=33, SCOPE PREFIX=0.
			[]byte{0x00, 0x01, 0x21, 0x00},
			// ADDRESS: ceil(33/8)=5 bytes.
			[]byte{0x01, 0x02, 0x03, 0x04, 0x80},
		),
	}, {
		// ECS with IPv6 source prefix length 129 (exceeds 128-bit).
		name: "ecs_ipv6_prefix_129",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=25 (4 option hdr + 21 ECS data).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19},
			// ECS option: CODE=8, LENGTH=21.
			[]byte{0x00, 0x08, 0x00, 0x15},
			// FAMILY=2(IPv6), SOURCE PREFIX=129, SCOPE PREFIX=0.
			[]byte{0x00, 0x02, 0x81, 0x00},
			// ADDRESS: ceil(129/8)=17 bytes.
			make([]byte, 17),
		),
	}, {
		// ECS with unsupported ADDRESS FAMILY=8.
		name: "ecs_unsupported_family",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=8 (4 option hdr + 4 ECS data).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
			// ECS option: CODE=8, LENGTH=4.
			[]byte{0x00, 0x08, 0x00, 0x04},
			// FAMILY=8(unsupported), SOURCE PREFIX=0, SCOPE PREFIX=0.
			[]byte{0x00, 0x08, 0x00, 0x00},
		),
	}, {
		// OPT RR with RDLEN indicating bytes but truncated option header (3
		// bytes where 4 needed for option CODE+LENGTH).
		name: "edns_option_header_truncated",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=3 (incomplete option header).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
			[]byte{0x00, 0x0A, 0x00},
		),
	}, {
		// COOKIE option with OPTION-CODE=8 instead of 10.
		name: "cookie_wrong_option_code",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=12 (4 hdr + 8 cookie data).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C},
			// Option CODE=8(ECS code), LENGTH=8, 8 bytes client cookie.
			[]byte{0x00, 0x08, 0x00, 0x08},
			bytes.Repeat([]byte{0xAA}, 8),
		),
	}, {
		// DAU option with OPTION-CODE=11 instead of 5.
		name: "dau_wrong_option_code",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=6 (4 hdr + 2 alg).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
			// Option CODE=11(KEEPALIVE code), LENGTH=2, alg list.
			[]byte{0x00, 0x0B, 0x00, 0x02, 0x08, 0x0D},
		),
	}, {
		// DHU option with OPTION-CODE=9 instead of 6.
		name: "dhu_wrong_option_code",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=6.
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
			// Option CODE=9(EXPIRE code), LENGTH=2, hash alg list.
			[]byte{0x00, 0x09, 0x00, 0x02, 0x01, 0x02},
		),
	}, {
		// DAU/DHU/N3U with LIST-LENGTH not matching actual list.
		name: "dau_list_length_mismatch",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=8 (4 hdr + 4 data).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
			// DAU option CODE=5, LENGTH=4, but only 2 algs meaningful.
			[]byte{0x00, 0x05, 0x00, 0x04, 0x08, 0x0D, 0x00, 0x00},
		),
	}, {
		// N3U option with OPTION-CODE=8 instead of 7.
		name: "n3u_wrong_option_code",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=5 (4 hdr + 1 alg).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
			// Option CODE=8(ECS code), LENGTH=1, 1 hash alg.
			[]byte{0x00, 0x08, 0x00, 0x01, 0x01},
		),
	}, {
		// ECS option with OPTION-CODE=10 instead of 8.
		name: "ecs_wrong_option_code",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=12 (4 hdr + 8 ECS data).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C},
			// Option CODE=10(COOKIE code), LENGTH=8.
			[]byte{0x00, 0x0A, 0x00, 0x08},
			// FAMILY=1(IPv4), SOURCE PREFIX=24, SCOPE=0, ADDR=192.168.1.
			[]byte{0x00, 0x01, 0x18, 0x00, 0xC0, 0xA8, 0x01, 0x00},
		),
	}, {
		// EDE option with OPTION-CODE=9 instead of 15.
		name: "ede_wrong_option_code",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=8 (4 hdr + 4 EDE data).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
			// Option CODE=9(EXPIRE), LENGTH=4, INFO-CODE=0, extra text "ab".
			[]byte{0x00, 0x09, 0x00, 0x04, 0x00, 0x00, 0x61, 0x62},
		),
	}, {
		// CHAIN option with OPTION-CODE=11 instead of 13.
		name: "chain_wrong_option_code",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=5 (4 hdr + 1 root name).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
			// Option CODE=11(KEEPALIVE), LENGTH=1, root domain.
			[]byte{0x00, 0x0B, 0x00, 0x01, 0x00},
		),
	}, {
		// EDNS option chain requiring maximum parser iterations.
		name: "edns_max_parser_iterations",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=200 (50 options * 4 bytes each).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC8},
			// 50 zero-length options with incrementing codes.
			func() (opts []byte) {
				for i := range 50 {
					opts = append(opts, 0x00, byte(i+1), 0x00, 0x00)
				}

				return opts
			}(),
		),
	}, {
		// EDNS option with OPTION-LENGTH=0 but option data present.
		name: "edns_option_length_zero_with_data",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=8.
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
			// Option CODE=10, LENGTH=0, then 4 garbage bytes within RDLEN.
			[]byte{0x00, 0x0A, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF},
		),
	}, {
		// EDNS options list with gap (option[0] and option[2], missing
		// option[1]).
		name: "edns_options_with_gap",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=8 (two zero-length options).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
			// Option CODE=5(DAU), LENGTH=0.
			[]byte{0x00, 0x05, 0x00, 0x00},
			// Option CODE=7(N3U), LENGTH=0 (skipping CODE=6).
			[]byte{0x00, 0x07, 0x00, 0x00},
		),
	}, {
		// EDNS options with same code repeated 10 times.
		name: "edns_duplicate_option_10x",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=40 (10 options * 4 bytes).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28},
			// 10x Option CODE=10(COOKIE), LENGTH=0.
			bytes.Repeat([]byte{0x00, 0x0A, 0x00, 0x00}, 10),
		),
	}, {
		// EXPIRE option with OPTION-CODE=11 instead of 9.
		name: "expire_wrong_option_code",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=8 (4 hdr + 4 expire data).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
			// Option CODE=11(KEEPALIVE), LENGTH=4, expire value.
			[]byte{0x00, 0x0B, 0x00, 0x04, 0x00, 0x00, 0x0E, 0x10},
		),
	}, {
		// KEY-TAG option with OPTION-CODE=8 instead of 14.
		name: "keytag_wrong_option_code",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=6 (4 hdr + 2 key tag).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
			// Option CODE=8(ECS), LENGTH=2, key tag=0x1234.
			[]byte{0x00, 0x08, 0x00, 0x02, 0x12, 0x34},
		),
	}, {
		// Multiple EDNS options each claiming large lengths.
		name: "edns_multiple_large_lengths",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=12.
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C},
			// Option 1: CODE=10, LENGTH=1000.
			[]byte{0x00, 0x0A, 0x03, 0xE8},
			// Option 2: CODE=12, LENGTH=2000.
			[]byte{0x00, 0x0C, 0x07, 0xD0},
			// Only 4 actual bytes remain.
			[]byte{0x00, 0x00, 0x00, 0x00},
		),
	}, {
		// TCP-KEEPALIVE option with OPTION-CODE=8 instead of 11.
		name: "keepalive_wrong_option_code",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=6 (4 hdr + 2 timeout).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
			// Option CODE=8(ECS), LENGTH=2, timeout=300.
			[]byte{0x00, 0x08, 0x00, 0x02, 0x01, 0x2C},
		),
	}, {
		// COOKIE option with client cookie being sequential counter.
		name: "cookie_sequential_counter",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=12 (4 hdr + 8 client cookie).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C},
			// COOKIE CODE=10, LENGTH=8, sequential counter client cookie.
			[]byte{0x00, 0x0A, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		),
	}, {
		// ECS with private IP but querying public DNS.
		name: "ecs_private_ip_public_dns",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=11 (4 hdr + 7 ECS data).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B},
			// ECS CODE=8, LENGTH=7.
			[]byte{0x00, 0x08, 0x00, 0x07},
			// FAMILY=1(IPv4), SOURCE PREFIX=24, SCOPE=0, ADDR=192.168.1.
			[]byte{0x00, 0x01, 0x18, 0x00, 0xC0, 0xA8, 0x01},
		),
	}, {
		// DAU option listing deprecated algorithm 1 (RSA/MD5).
		name: "dau_deprecated_algorithm",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=5.
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
			// DAU CODE=5, LENGTH=1, alg=1(RSA/MD5 deprecated).
			[]byte{0x00, 0x05, 0x00, 0x01, 0x01},
		),
	}, {
		// ECS with SCOPE PREFIX-LENGTH non-zero in query.
		name: "ecs_scope_prefix_nonzero_in_query",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=11.
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B},
			// ECS CODE=8, LENGTH=7.
			[]byte{0x00, 0x08, 0x00, 0x07},
			// FAMILY=1, SOURCE PREFIX=24, SCOPE=16 (non-zero in query!).
			[]byte{0x00, 0x01, 0x18, 0x10, 0x0A, 0x00, 0x01},
		),
	}, {
		// ECS query with SCOPE PREFIX-LENGTH=18.
		name: "ecs_scope_prefix_18",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=11.
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B},
			// ECS CODE=8, LENGTH=7.
			[]byte{0x00, 0x08, 0x00, 0x07},
			// FAMILY=1, SOURCE PREFIX=24, SCOPE=18.
			[]byte{0x00, 0x01, 0x18, 0x12, 0x0A, 0x00, 0x01},
		),
	}, {
		// ECS source prefix length set to 255 (exceeds IP bits).
		name: "ecs_source_prefix_255",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=36 (4 hdr + 32 ECS data: 4 hdr + ceil(255/8)
			// bytes addr).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24},
			// ECS CODE=8, LENGTH=36.
			[]byte{0x00, 0x08, 0x00, 0x24},
			// FAMILY=1(IPv4), SOURCE PREFIX=255, SCOPE=0.
			[]byte{0x00, 0x01, 0xFF, 0x00},
			// ceil(255/8)=32 bytes of address.
			make([]byte, 32),
		),
	}, {
		// ECS with source prefix length 0 (no client subnet info).
		name: "ecs_source_prefix_zero",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=8 (4 hdr + 4 ECS data).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
			// ECS CODE=8, LENGTH=4.
			[]byte{0x00, 0x08, 0x00, 0x04},
			// FAMILY=1(IPv4), SOURCE PREFIX=0, SCOPE=0.
			[]byte{0x00, 0x01, 0x00, 0x00},
		),
	}, {
		// EDNS Padding with non-zero bytes (should be zero).
		name: "edns_padding_nonzero",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=14 (4 hdr + 10 padding data).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E},
			// Padding CODE=12, LENGTH=10, non-zero bytes.
			[]byte{0x00, 0x0C, 0x00, 0x0A},
			bytes.Repeat([]byte{0xFF}, 10),
		),
	}, {
		// Internal query with ECS indicating external client subnet.
		name: "ecs_internal_query_external_subnet",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=11.
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B},
			// ECS CODE=8, LENGTH=7.
			[]byte{0x00, 0x08, 0x00, 0x07},
			// FAMILY=1, SOURCE PREFIX=24, SCOPE=0, ADDR=8.8.8 (public).
			[]byte{0x00, 0x01, 0x18, 0x00, 0x08, 0x08, 0x08},
		),
	}, {
		// NSEC3 parameters requested but N3U algorithm list empty.
		name: "n3u_empty_algorithm_list",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=4 (option with zero-length data).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
			// N3U CODE=7, LENGTH=0 (empty algorithm list).
			[]byte{0x00, 0x07, 0x00, 0x00},
		),
	}, {
		// OPT RR RDLEN indicates 50 bytes but options list is empty.
		name: "opt_rdlen_50_no_options",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=50, but fill with zeros (no valid option
			// headers).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32},
			make([]byte, 50),
		),
	}, {
		// OPT RR RDLEN=10 but actual options length=5.
		name: "opt_rdlen_10_options_5",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=10.
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A},
			// Option CODE=10, LENGTH=1, DATA=1 byte (5 bytes total option).
			[]byte{0x00, 0x0A, 0x00, 0x01, 0xAA},
			// 5 trailing garbage bytes within RDLEN.
			[]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00},
		),
	}, {
		// Padding option with prime number length (789 bytes).
		name: "edns_padding_prime_length",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=793 (4 hdr + 789 padding).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x03, 0x19},
			// Padding CODE=12, LENGTH=789.
			[]byte{0x00, 0x0C, 0x03, 0x15},
			make([]byte, 789),
		),
	}, {
		// ECS indicating internal subnet from external source.
		name: "ecs_external_source_internal_subnet",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=11.
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B},
			// ECS CODE=8, LENGTH=7.
			[]byte{0x00, 0x08, 0x00, 0x07},
			// FAMILY=1, SOURCE PREFIX=24, SCOPE=0, ADDR=10.0.1 (private).
			[]byte{0x00, 0x01, 0x18, 0x00, 0x0A, 0x00, 0x01},
		),
	}, {
		// OPT RR header complete but RDATA truncated.
		name: "opt_rdata_truncated",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=20, but only 5 bytes of RDATA follow.
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14},
			[]byte{0x00, 0x0A, 0x00, 0x01, 0xAA},
		),
	}, {
		// Maximum EDNS padding to inflate traffic.
		name: "edns_max_padding",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=1200 (4 hdr + 1196 padding).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x04, 0xB0},
			// Padding CODE=12, LENGTH=1196.
			[]byte{0x00, 0x0C, 0x04, 0xAC},
			make([]byte, 1196),
		),
	}, {
		// ZONEVERSION option without corresponding SOA query.
		name: "zoneversion_without_soa",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=4.
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
			// ZONEVERSION CODE=19, LENGTH=0.
			[]byte{0x00, 0x13, 0x00, 0x00},
		),
	}, {
		// EDNS option chain with backward option code ordering.
		name: "edns_backward_code_ordering",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=12 (3 zero-length options).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C},
			// Options in descending code order: 12, 10, 5.
			[]byte{0x00, 0x0C, 0x00, 0x00},
			[]byte{0x00, 0x0A, 0x00, 0x00},
			[]byte{0x00, 0x05, 0x00, 0x00},
		),
	}, {
		// EDNS option with code gaps (5,7,9,11 — missing even codes).
		name: "edns_option_code_gaps",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=16 (4 zero-length options).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
			[]byte{0x00, 0x05, 0x00, 0x00},
			[]byte{0x00, 0x07, 0x00, 0x00},
			[]byte{0x00, 0x09, 0x00, 0x00},
			[]byte{0x00, 0x0B, 0x00, 0x00},
		),
	}, {
		// EDNS options with duplicate option codes.
		name: "edns_duplicate_option_codes",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=8 (2 zero-length options, same code).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
			[]byte{0x00, 0x0A, 0x00, 0x00},
			[]byte{0x00, 0x0A, 0x00, 0x00},
		),
	}, {
		// Padding option with OPTION-CODE=11 instead of 12.
		name: "padding_wrong_option_code",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=14 (4 hdr + 10 padding).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E},
			// Option CODE=11(KEEPALIVE), LENGTH=10, zero padding bytes.
			[]byte{0x00, 0x0B, 0x00, 0x0A},
			make([]byte, 10),
		),
	}, {
		// EDNS padding option at the beginning instead of end.
		name: "edns_padding_at_beginning",
		data: slices.Concat(
			newTestHdr(t, dns.Header{Id: dns.Id(), Bits: testHdrBits, Qdcount: 1, Arcount: 1}),
			rootQuestion,
			// OPT RR: RDLENGTH=18 (padding 10 + cookie 8).
			[]byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12},
			// Padding CODE=12, LENGTH=10 (at beginning).
			[]byte{0x00, 0x0C, 0x00, 0x0A},
			make([]byte, 10),
			// COOKIE CODE=10, LENGTH=0 (after padding).
			[]byte{0x00, 0x0A, 0x00, 0x00},
		),
	}}

	for _, tc := range testCases {
		conf := &dnsserver.ConfigDNS{
			Base: &dnsserver.ConfigBase{Handler: dnsservertest.NewPanicHandler()},
		}

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var invalidMsgCh chan unit
			conf.Base.Metrics, invalidMsgCh = newInvalidMsgMetrics(t)

			_, addr := dnsservertest.RunDNSServer(t, conf)

			conn, err := net.Dial("tcp", addr)
			require.NoError(t, err)
			testutil.CleanupAndRequireSuccess(t, conn.Close)

			deadline := time.Now().Add(testTimeout)
			require.NoError(t, conn.SetDeadline(deadline))

			err = binary.Write(conn, binary.BigEndian, uint16(len(tc.data)))
			require.NoError(t, err)

			n, err := conn.Write(tc.data)
			require.NoError(t, err)
			require.Equal(t, len(tc.data), n)

			_, ok := testutil.RequireReceive(t, invalidMsgCh, testTimeout)
			require.True(t, ok)
		})
	}
}
