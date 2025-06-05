package dnsserver_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
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

// readMsg is a helper function for reading DNS responses from a plain DNS
// connection.  network must be either [dnsserver.NetworkUDP] or
// [dnsserver.NetworkTCP].
func readMsg(tb testing.TB, resBuf []byte, network dnsserver.Network, conn net.Conn) {
	tb.Helper()

	var n int

	switch network {
	case dnsserver.NetworkUDP:
		var err error
		n, err = conn.Read(resBuf)
		require.NoError(tb, err)
	case dnsserver.NetworkTCP:
		var length uint16
		err := binary.Read(conn, binary.BigEndian, &length)
		require.NoError(tb, err)

		n, err = io.ReadFull(conn, resBuf[:length])
		require.NoError(tb, err)
	default:
		panic(fmt.Errorf("network type: %w: %q", errors.ErrBadEnumValue, network))
	}

	require.GreaterOrEqual(tb, n, dnsserver.DNSHeaderSize)
}

func BenchmarkServeDNS(b *testing.B) {
	msg := (&dns.Msg{}).SetQuestion("example.org.", dns.TypeA)

	udpPacket, packErr := msg.Pack()
	require.NoError(b, packErr)

	tcpPacket := make([]byte, 2+len(udpPacket))
	binary.BigEndian.PutUint16(tcpPacket, uint16(len(udpPacket)))
	copy(tcpPacket[2:], udpPacket)

	benchCases := []struct {
		network dnsserver.Network
		name    string
		packet  []byte
	}{{
		network: dnsserver.NetworkUDP,
		name:    "udp",
		packet:  udpPacket,
	}, {
		network: dnsserver.NetworkTCP,
		name:    "tcp",
		packet:  tcpPacket,
	}}

	for _, bc := range benchCases {
		_, addr := dnsservertest.RunDNSServer(b, dnsservertest.NewDefaultHandler())

		// Open connection (using one to avoid client-side allocations).
		conn, err := net.Dial(string(bc.network), addr)
		require.NoError(b, err)

		// Prepare a buffer to read responses.
		resBuf := make([]byte, 512)

		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, err = conn.Write(bc.packet)
				require.NoError(b, err)

				readMsg(b, resBuf, bc.network, conn)
			}
		})
	}

	// Most recent results:
	//
	// goos: darwin
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsserver
	// cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	// BenchmarkServeDNS/udp-12         	   25738	     47458 ns/op	    2414 B/op	      36 allocs/op
	// BenchmarkServeDNS/tcp-12         	   28801	     40789 ns/op	    2317 B/op	      35 allocs/op
}

func BenchmarkServeTLS(b *testing.B) {
	tlsConfig := dnsservertest.CreateServerTLSConfig("example.org")
	addr := dnsservertest.RunTLSServer(b, dnsservertest.NewDefaultHandler(), tlsConfig)

	m := (&dns.Msg{}).SetQuestion("example.org.", dns.TypeA)

	data, _ := m.Pack()
	msg := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(msg, uint16(len(data)))
	copy(msg[2:], data)

	tcpConn, err := net.DialTCP("tcp", nil, addr)
	require.NoError(b, err)

	conn := tls.Client(tcpConn, tlsConfig)
	err = conn.Handshake()
	require.NoError(b, err)

	resBuf := make([]byte, 512)

	b.ReportAllocs()
	for b.Loop() {
		_, err = conn.Write(msg)
		require.NoError(b, err)

		readMsg(b, resBuf, dnsserver.NetworkTCP, conn)
	}

	// Most recent results:
	//
	// goos: darwin
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsserver
	// cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	// BenchmarkServeTLS-12    	   26343	     45694 ns/op	    2367 B/op	      37 allocs/op
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
		http3Enabled: false,
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
				return srv.Shutdown(testutil.ContextWithTimeout(b, testTimeout))
			})

			m := (&dns.Msg{}).SetQuestion("example.org.", dns.TypeA)
			data, err := m.Pack()
			require.NoError(b, err)

			msg := make([]byte, 2+len(data))
			binary.BigEndian.PutUint16(msg, uint16(len(data)))
			copy(msg[2:], data)

			addr := srv.LocalTCPAddr()
			if tc.http3Enabled {
				addr = srv.LocalUDPAddr()
			}

			client, err := newDoHClient(addr, tc.tlsConfig)
			require.NoError(b, err)

			req, err := newDoHRequest(http.MethodPost, m, tc.tlsConfig != nil)
			require.NoError(b, err)

			var res *http.Response
			var buf []byte

			b.ReportAllocs()
			for b.Loop() {
				res, err = client.Do(req)
				require.NoError(b, err)

				buf, err = io.ReadAll(res.Body)
				require.NoError(b, err)

				err = res.Body.Close()
				require.NoError(b, err)
				require.GreaterOrEqual(b, len(buf), dnsserver.DNSHeaderSize)
			}
		})
	}

	// Most recent results:
	//
	// goos: darwin
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsserver
	// cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	// BenchmarkServeDoH/doh2-12         	    8448	    144691 ns/op	   11987 B/op	     125 allocs/op
	// BenchmarkServeDoH/doh3-12         	    6675	    179742 ns/op	   27085 B/op	     289 allocs/op
	// BenchmarkServeDoH/plain_http-12   	    5023	    244999 ns/op	   25639 B/op	     212 allocs/op
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
		req := (&dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:               dns.Id(),
				RecursionDesired: true,
			},
			Question: []dns.Question{{
				Name:   "example.org.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		})
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

		ri, err := client.DialStamp(stamp)
		require.NoError(b, err)
		require.NotNil(b, ri)

		conn, err := net.Dial(string(tc.network), stamp.ServerAddrStr)
		require.NoError(b, err)

		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var resp *dns.Msg
				resp, err = client.ExchangeConn(conn, req, ri)
				require.NoError(b, err)
				require.True(b, resp.Response)
			}
		})
	}

	// Most recent results:
	//
	// goos: darwin
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsserver
	// cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	// BenchmarkServeDNSCrypt/udp-12         	    4213	    268778 ns/op	    6887 B/op	      80 allocs/op
	// BenchmarkServeDNSCrypt/tcp-12         	    5266	    242573 ns/op	    5371 B/op	      75 allocs/op
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

	req := (&dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   "example.org.",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	})

	sess, err := quic.DialAddr(context.Background(), addr.String(), tlsConfig, nil)
	require.NoError(b, err)
	testutil.CleanupAndRequireSuccess(b, func() (err error) {
		return sess.CloseWithError(0, "")
	})

	b.ReportAllocs()
	for b.Loop() {
		resp := requireSendQUICMessage(b, sess, req)
		require.NotNil(b, resp)
		require.True(b, resp.Response)
	}

	// Most recent results:
	//
	// goos: darwin
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsserver
	// cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	// BenchmarkServeQUIC-12    	    7291	    166588 ns/op	  101835 B/op	     153 allocs/op
}
