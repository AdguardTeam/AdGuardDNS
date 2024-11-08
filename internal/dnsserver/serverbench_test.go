package dnsserver_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

// TODO(ameshkov, a.garipov):  Move into the corresponding files.

func BenchmarkServeDNS(b *testing.B) {
	testCases := []struct {
		name    string
		network dnsserver.Network
	}{{
		name:    "udp",
		network: dnsserver.NetworkUDP,
	}, {
		name:    "tcp",
		network: dnsserver.NetworkTCP,
	}}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			_, addr := dnsservertest.RunDNSServer(b, dnsservertest.NewDefaultHandler())

			// Prepare a test message.
			m := new(dns.Msg)
			m.SetQuestion("example.org.", dns.TypeA)
			var msg []byte
			msgPacket, _ := m.Pack()
			if tc.network == dnsserver.NetworkTCP {
				msg = make([]byte, 2+len(msgPacket))
				binary.BigEndian.PutUint16(msg, uint16(len(msgPacket)))
				copy(msg[2:], msgPacket)
			} else {
				msg, _ = m.Pack()
			}

			// Open connection (using one to avoid client-side allocations).
			conn, err := net.Dial(string(tc.network), addr)
			require.NoError(b, err)

			// Prepare a buffer to read responses.
			resBuf := make([]byte, 512)

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_, err = conn.Write(msg)
				require.NoError(b, err)

				err = readMsg(resBuf, tc.network, conn)
				require.NoError(b, err)
			}
		})
	}
}

// readMsg is a helper function for reading DNS responses from a plain DNS
// connection.
func readMsg(resBuf []byte, network dnsserver.Network, conn net.Conn) (err error) {
	defer func() { err = errors.Annotate(err, "failed to read DNS msg: %w") }()

	var n int

	if network == dnsserver.NetworkTCP {
		var length uint16
		if err = binary.Read(conn, binary.BigEndian, &length); err != nil {
			return err
		}

		n, err = io.ReadFull(conn, resBuf[:length])
		if err != nil {
			return err
		}
	} else {
		n, err = conn.Read(resBuf)
		if err != nil {
			return err
		}
	}

	if n < dnsserver.DNSHeaderSize {
		return dns.ErrShortRead
	}

	return nil
}

func BenchmarkServeTLS(b *testing.B) {
	tlsConfig := dnsservertest.CreateServerTLSConfig("example.org")
	addr := dnsservertest.RunTLSServer(b, dnsservertest.NewDefaultHandler(), tlsConfig)

	// Prepare a test message
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	data, _ := m.Pack()
	msg := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(msg, uint16(len(data)))
	copy(msg[2:], data)

	// Open a TCP connection (using one to avoid client-side allocations)
	tcpConn, err := net.DialTCP("tcp", nil, addr)
	require.NoError(b, err)

	// Now create a TLS connection over that TCP one
	conn := tls.Client(tcpConn, tlsConfig)
	err = conn.Handshake()
	require.NoError(b, err)

	// Prepare a buffer to read responses
	resBuf := make([]byte, 512)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, err = conn.Write(msg)
		require.NoError(b, err)

		var length uint16
		if err = binary.Read(conn, binary.BigEndian, &length); err != nil {
			b.Fatalf("failed to read the DNS query response: %v", err)
		}

		var n int
		n, err = io.ReadFull(conn, resBuf[:length])
		if err != nil {
			b.Fatalf("failed to read the DNS query response: %v", err)
		}

		require.GreaterOrEqual(b, n, dnsserver.DNSHeaderSize)
	}
}

func BenchmarkServeDoH(b *testing.B) {
	testCases := []struct {
		tlsConfig    *tls.Config
		name         string
		https        bool
		http3Enabled bool
	}{{
		tlsConfig:    dnsservertest.CreateServerTLSConfig("example.org"),
		name:         "doh2",
		http3Enabled: false,
	}, {
		tlsConfig:    dnsservertest.CreateServerTLSConfig("example.org"),
		name:         "doh3",
		http3Enabled: true,
	}, {
		tlsConfig:    nil,
		name:         "plain_http",
		http3Enabled: true,
	}}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			srv, err := dnsservertest.RunLocalHTTPSServer(
				dnsservertest.NewDefaultHandler(),
				tc.tlsConfig,
				nil,
			)
			require.NoError(b, err)

			testutil.CleanupAndRequireSuccess(b, func() (err error) {
				return srv.Shutdown(context.Background())
			})

			// Prepare a test message.
			m := (&dns.Msg{}).SetQuestion("example.org.", dns.TypeA)
			data, err := m.Pack()
			require.NoError(b, err)

			msg := make([]byte, 2+len(data))
			binary.BigEndian.PutUint16(msg, uint16(len(data)))
			copy(msg[2:], data)

			// Prepare client.
			addr := srv.LocalTCPAddr()
			if tc.http3Enabled {
				addr = srv.LocalUDPAddr()
			}

			client, err := newDoHClient(addr, tc.tlsConfig)
			require.NoError(b, err)

			// Prepare http.Request.
			req, err := newDoHRequest(http.MethodPost, m, tc.tlsConfig != nil)
			require.NoError(b, err)

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				var res *http.Response
				res, err = client.Do(req)
				require.NoError(b, err)

				var buf []byte
				buf, err = io.ReadAll(res.Body)
				require.NoError(b, err)

				err = res.Body.Close()
				require.NoError(b, err)
				require.GreaterOrEqual(b, len(buf), dnsserver.DNSHeaderSize)
			}
		})
	}
}

func BenchmarkServeDNSCrypt(b *testing.B) {
	testCases := []struct {
		name    string
		network dnsserver.Network
	}{{
		name:    "udp",
		network: dnsserver.NetworkUDP,
	}, {
		name:    "tcp",
		network: dnsserver.NetworkTCP,
	}}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			// Create a test message
			req := new(dns.Msg)
			req.Id = dns.Id()
			req.RecursionDesired = true
			name := "example.org."
			req.Question = []dns.Question{
				{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET},
			}

			client := &dnscrypt.Client{
				Timeout: 1 * time.Second,
				Net:     string(tc.network),
			}

			s := dnsservertest.RunDNSCryptServer(b, dnsservertest.NewDefaultHandler())
			stamp := dnsstamps.ServerStamp{
				ServerAddrStr: s.ServerAddr,
				ServerPk:      s.ResolverPk,
				ProviderName:  s.ProviderName,
				Proto:         dnsstamps.StampProtoTypeDNSCrypt,
			}

			// Load server info
			ri, err := client.DialStamp(stamp)
			require.NoError(b, err)
			require.NotNil(b, ri)

			// Open a single connection
			conn, err := net.Dial(string(tc.network), stamp.ServerAddrStr)
			require.NoError(b, err)

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				var resp *dns.Msg
				resp, err = client.ExchangeConn(conn, req, ri)
				require.NoError(b, err)
				require.True(b, resp.Response)
			}
		})
	}
}

func BenchmarkServeQUIC(b *testing.B) {
	tlsConfig := dnsservertest.CreateServerTLSConfig("example.org")
	srv, addr, err := dnsservertest.RunLocalQUICServer(
		dnsservertest.NewDefaultHandler(),
		tlsConfig,
	)
	require.NoError(b, err)

	testutil.CleanupAndRequireSuccess(b, func() (err error) {
		return srv.Shutdown(context.Background())
	})

	// Create a test message
	req := new(dns.Msg)
	req.Id = dns.Id()
	req.RecursionDesired = true
	name := "example.org."
	req.Question = []dns.Question{
		{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	// Open QUIC session
	sess, err := quic.DialAddr(context.Background(), addr.String(), tlsConfig, nil)
	require.NoError(b, err)
	defer func() {
		err = sess.CloseWithError(0, "")
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		resp := requireSendQUICMessage(b, sess, req)
		require.NotNil(b, resp)
		require.True(b, resp.Response)
	}
}
