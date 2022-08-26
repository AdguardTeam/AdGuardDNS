package dnsserver_test

import (
	"context"
	"encoding/binary"
	"io"
	"sync"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
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
	conn, err := quic.DialAddr(addr.String(), tlsConfig, nil)
	require.NoError(t, err)

	defer func(conn quic.Connection, code quic.ApplicationErrorCode, s string) {
		_ = conn.CloseWithError(code, s)
	}(conn, 0, "")

	// Send multiple queries to the DNS server in parallel
	wg := &sync.WaitGroup{}

	for i := 0; i < 100; i++ {
		wg.Add(1)

		// Create a test message.
		req := dnsservertest.NewReq("example.org.", dns.TypeA, dns.ClassINET)
		req.RecursionDesired = true

		// even requests are sent as if it's an old draft client.
		doqDraft := i%2 == 0
		go func() {
			defer wg.Done()

			res, qerr := sendQUICMessage(conn, req, doqDraft)
			assert.NoError(t, qerr)
			assert.NotNil(t, res)
			assert.True(t, res.Response)
		}()
	}

	wg.Wait()
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

	// Send the DNS query to the stream.
	_, err = stream.Write(buf)
	if err != nil {
		return nil, err
	}

	// Close closes the write-direction of the stream
	// and sends a STREAM FIN packet.
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
