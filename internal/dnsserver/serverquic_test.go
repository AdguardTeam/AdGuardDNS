package dnsserver_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerQUIC_integration_query(t *testing.T) {
	tlsConfig := dnsservertest.CreateServerTLSConfig("example.org")
	srv, addr, err := dnsservertest.RunLocalQUICServer(
		dnsservertest.DefaultHandler(),
		tlsConfig,
	)
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return srv.Shutdown(context.Background())
	})

	// Open a QUIC connection.
	conn, err := quic.DialAddr(context.Background(), addr.String(), tlsConfig, nil)
	require.NoError(t, err)

	defer testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return conn.CloseWithError(0, "")
	})

	// Send multiple queries to the DNS server in parallel
	wg := &sync.WaitGroup{}

	for i := 0; i < 100; i++ {
		wg.Add(1)

		// Create a test message.
		req := dnsservertest.NewReq("example.org.", dns.TypeA, dns.ClassINET)
		req.RecursionDesired = true

		// Even requests are sent as if it's an old draft client.
		doqDraft := i%2 == 0
		go func() {
			defer wg.Done()

			resp, qerr := sendQUICMessage(conn, req, doqDraft)
			assert.NoError(t, qerr)
			assert.NotNil(t, resp)
			assert.True(t, resp.Response)

			// EDNS0 padding is only present when request also has padding opt.
			paddingOpt := dnsservertest.FindEDNS0Option[*dns.EDNS0_PADDING](resp)
			require.Nil(t, paddingOpt)
		}()
	}

	wg.Wait()
}

func TestServerQUIC_integration_ENDS0Padding(t *testing.T) {
	tlsConfig := dnsservertest.CreateServerTLSConfig("example.org")
	srv, addr, err := dnsservertest.RunLocalQUICServer(
		dnsservertest.DefaultHandler(),
		tlsConfig,
	)
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return srv.Shutdown(context.Background())
	})

	// Open a QUIC connection.
	conn, err := quic.DialAddr(context.Background(), addr.String(), tlsConfig, nil)
	require.NoError(t, err)

	defer func(conn quic.Connection, code quic.ApplicationErrorCode, s string) {
		_ = conn.CloseWithError(code, s)
	}(conn, 0, "")

	req := dnsservertest.CreateMessage("example.org.", dns.TypeA)
	req.Extra = []dns.RR{dnsservertest.NewEDNS0Padding(req.Len(), dns.DefaultMsgSize)}

	resp, qerr := sendQUICMessage(conn, req, false)
	require.NoError(t, qerr)
	require.NotNil(t, resp)
	require.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.True(t, resp.Response)
	require.False(t, resp.Truncated)

	paddingOpt := dnsservertest.FindEDNS0Option[*dns.EDNS0_PADDING](resp)
	require.NotNil(t, paddingOpt)
	require.NotEmpty(t, paddingOpt.Padding)
}

func TestServerQUIC_integration_0RTT(t *testing.T) {
	tlsConfig := dnsservertest.CreateServerTLSConfig("example.org")
	srv, addr, err := dnsservertest.RunLocalQUICServer(
		dnsservertest.DefaultHandler(),
		tlsConfig,
	)
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return srv.Shutdown(context.Background())
	})

	quicTracer := &dnsservertest.QUICTracer{}

	// quicConfig with TokenStore set so that 0-RTT was enabled.
	quicConfig := &quic.Config{
		TokenStore: quic.NewLRUTokenStore(1, 10),
		Tracer:     quicTracer.TracerForConnection,
	}

	// ClientSessionCache in the tls.Config must also be set for 0-RTT to work.
	clientTLSConfig := tlsConfig.Clone()
	clientTLSConfig.ClientSessionCache = tls.NewLRUClientSessionCache(10)

	// Use the first connection (no 0-RTT).
	testQUICExchange(t, addr, clientTLSConfig, quicConfig)

	// Use the second connection (now 0-RTT should kick in).
	testQUICExchange(t, addr, clientTLSConfig, quicConfig)

	// Verify how 0-RTT was used.
	conns := quicTracer.ConnectionsInfo()

	require.Len(t, conns, 2)
	require.False(t, conns[0].Is0RTT())
	require.True(t, conns[1].Is0RTT())
}

func TestServerQUIC_integration_largeQuery(t *testing.T) {
	tlsConfig := dnsservertest.CreateServerTLSConfig("example.org")
	srv, addr, err := dnsservertest.RunLocalQUICServer(
		dnsservertest.DefaultHandler(),
		tlsConfig,
	)
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return srv.Shutdown(context.Background())
	})

	// Open a QUIC connection.
	conn, err := quic.DialAddr(context.Background(), addr.String(), tlsConfig, nil)
	require.NoError(t, err)

	defer testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return conn.CloseWithError(0, "")
	})

	// Create a test message large enough so that it was sent using multiple
	// QUIC frames.
	req := dnsservertest.NewReq("example.org.", dns.TypeA, dns.ClassINET)
	req.RecursionDesired = true
	req.Extra = []dns.RR{
		&dns.OPT{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096},
			Option: []dns.EDNS0{
				&dns.EDNS0_PADDING{Padding: make([]byte, 4096)},
			},
		},
	}

	resp, err := sendQUICMessage(conn, req, false)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.Response)
}

// testQUICExchange initializes a new QUIC connection and sends one test DNS
// query through it.
func testQUICExchange(
	t *testing.T,
	addr *net.UDPAddr,
	tlsConfig *tls.Config,
	quicConfig *quic.Config,
) {
	conn, err := quic.DialAddrEarly(context.Background(), addr.String(), tlsConfig, quicConfig)
	require.NoError(t, err)

	defer testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return conn.CloseWithError(0, "")
	})

	defer func(conn quic.Connection, code quic.ApplicationErrorCode, s string) {
		_ = conn.CloseWithError(code, s)
	}(conn, 0, "")

	// Create a test message.
	req := dnsservertest.NewReq("example.org.", dns.TypeA, dns.ClassINET)
	req.RecursionDesired = true

	resp, err := sendQUICMessage(conn, req, false)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// sendQUICMessage sends a test QUIC message.
func sendQUICMessage(conn quic.Connection, req *dns.Msg, doqDraft bool) (*dns.Msg, error) {
	// Open stream.
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	defer log.OnCloserError(stream, log.DEBUG)

	// Prepare a message to be written.
	data, err := req.Pack()
	if err != nil {
		return nil, err
	}

	var buf []byte
	if doqDraft {
		buf = data
	} else {
		buf = make([]byte, 2+len(data))
		binary.BigEndian.PutUint16(buf, uint16(len(data)))
		copy(buf[2:], data)
	}

	err = writeQUICStream(buf, stream)
	if err != nil {
		return nil, err
	}

	// Closes the write-direction of the stream and sends a STREAM FIN packet.
	// A DoQ client MUST send a FIN packet to indicate that the query is
	// finished.
	_ = stream.Close()

	// Now read the response.
	respBytes := make([]byte, dns.MaxMsgSize)
	n, err := stream.Read(respBytes)
	if err != nil && !errors.Is(err, io.EOF) {
		// Ignore EOF, this is just server sending FIN alongside the data
		return nil, err
	}

	if n < dnsserver.DNSHeaderSize {
		return nil, dns.ErrShortRead
	}

	// Unpack the response.
	reply := &dns.Msg{}
	if doqDraft {
		err = reply.Unpack(respBytes[:n])
	} else {
		err = reply.Unpack(respBytes[2:n])
	}
	if err != nil {
		return nil, err
	}

	return reply, nil
}

// writeQUICStream writes buf to the specified QUIC stream in chunks.  This way
// it is possible to test how the server deals with chunked DNS messages.
func writeQUICStream(buf []byte, stream quic.Stream) (err error) {
	// Send the DNS query to the stream and split it into chunks of up
	// to 400 bytes.  400 is an arbitrary chosen value.
	chunkSize := 400
	for i := 0; i < len(buf); i += chunkSize {
		chunkStart := i
		chunkEnd := i + chunkSize
		if chunkEnd > len(buf) {
			chunkEnd = len(buf)
		}

		_, err = stream.Write(buf[chunkStart:chunkEnd])
		if err != nil {
			return err
		}

		if len(buf) > chunkSize {
			// Emulate network latency.
			time.Sleep(time.Millisecond)
		}
	}

	return nil
}
