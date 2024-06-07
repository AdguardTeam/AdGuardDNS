package dnsserver_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
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
		return srv.Shutdown(testutil.ContextWithTimeout(t, testTimeout))
	})

	// Open a QUIC connection.
	conn, err := quic.DialAddr(context.Background(), addr.String(), tlsConfig, nil)
	require.NoError(t, err)

	defer testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return conn.CloseWithError(0, "")
	})

	const queriesNum = 100

	wg := &sync.WaitGroup{}
	wg.Add(queriesNum)

	for range queriesNum {
		req := dnsservertest.NewReq("example.org.", dns.TypeA, dns.ClassINET)
		req.RecursionDesired = true

		go func() {
			defer wg.Done()

			resp, reqErr := sendQUICMessage(conn, req)
			// Do not use require, as this is a separate goroutine.
			if !assert.NoError(t, reqErr) || !assert.NotNil(t, resp) {
				return
			}

			assert.True(t, resp.Response)

			// EDNS0 padding is only present when request also has padding opt.
			paddingOpt := dnsservertest.FindEDNS0Option[*dns.EDNS0_PADDING](resp)
			assert.Nil(t, paddingOpt)
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
		return srv.Shutdown(testutil.ContextWithTimeout(t, testTimeout))
	})

	// Open a QUIC connection.
	conn, err := quic.DialAddr(context.Background(), addr.String(), tlsConfig, nil)
	require.NoError(t, err)

	defer func(conn quic.Connection, code quic.ApplicationErrorCode, s string) {
		_ = conn.CloseWithError(code, s)
	}(conn, 0, "")

	req := dnsservertest.CreateMessage("example.org.", dns.TypeA)
	req.Extra = []dns.RR{dnsservertest.NewEDNS0Padding(req.Len(), dns.DefaultMsgSize)}

	resp := requireSendQUICMessage(t, conn, req)
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
		return srv.Shutdown(testutil.ContextWithTimeout(t, testTimeout))
	})

	quicTracer := dnsservertest.NewQUICTracer()

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
		return srv.Shutdown(testutil.ContextWithTimeout(t, testTimeout))
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

	resp := requireSendQUICMessage(t, conn, req)
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

	resp := requireSendQUICMessage(t, conn, req)
	require.NotNil(t, resp)
}

// sendQUICMessage is a test helper that sends a test QUIC message.
func sendQUICMessage(
	conn quic.Connection,
	req *dns.Msg,
) (resp *dns.Msg, err error) {
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, fmt.Errorf("opening stream: %w", err)
	}

	defer log.OnCloserError(stream, log.ERROR)

	data, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing: %w", err)
	}

	buf := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(buf, uint16(len(data)))
	copy(buf[2:], data)

	err = writeQUICStream(buf, stream)
	if err != nil {
		return nil, fmt.Errorf("writing: %w", err)
	}

	// Closes the write-direction of the stream and sends a STREAM FIN packet.
	// A DoQ client MUST send a FIN packet to indicate that the query is
	// finished.
	err = stream.Close()
	if err != nil {
		return nil, fmt.Errorf("closing stream: %w", err)
	}

	respBytes := make([]byte, dns.MaxMsgSize)
	n, err := stream.Read(respBytes)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading stream: %w", err)
	}

	if n < dnsserver.DNSHeaderSize {
		return nil, fmt.Errorf("read %d, want %d", n, dnsserver.DNSHeaderSize)
	}

	reply := &dns.Msg{}
	err = reply.Unpack(respBytes[2:n])
	if err != nil {
		return nil, fmt.Errorf("unpacking: %w", err)
	}

	return reply, nil
}

// requireSendQUICMessage is a test helper that sends a test QUIC message and
// requires it to succeed.  It must not be used in a goroutine with the outer
// test's t.
func requireSendQUICMessage(
	t testing.TB,
	conn quic.Connection,
	req *dns.Msg,
) (resp *dns.Msg) {
	t.Helper()

	resp, err := sendQUICMessage(conn, req)
	require.NoError(t, err)

	return resp
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
