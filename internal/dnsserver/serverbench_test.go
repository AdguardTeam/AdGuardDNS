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
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/ameshkov/dnsstamps"
	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func BenchmarkServeUDP(b *testing.B) {
	srv, _, err := dnsservertest.RunLocalDNSServer(
		dnsservertest.DefaultHandler(),
		dnsserver.ProtoDNSUDP,
	)
	require.NoError(b, err)

	testutil.CleanupAndRequireSuccess(b, func() (err error) {
		return srv.Shutdown(context.Background())
	})

	// Prepare a test message
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	msg, _ := m.Pack()

	// Open a UDP connection (using one to avoid client-side allocations)
	conn, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	require.NoError(b, err)

	// Prepare a buffer to read responses
	resBuf := make([]byte, 512)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = conn.Write(msg)
		require.NoError(b, err)

		var n int
		n, err = conn.Read(resBuf)
		require.NoError(b, err)
		require.GreaterOrEqual(b, n, dnsserver.DNSHeaderSize)
	}
	b.StopTimer()
}

func BenchmarkServeTCP(b *testing.B) {
	srv, _, err := dnsservertest.RunLocalDNSServer(
		dnsservertest.DefaultHandler(),
		dnsserver.ProtoDNSTCP)
	require.NoError(b, err)

	testutil.CleanupAndRequireSuccess(b, func() (err error) {
		return srv.Shutdown(context.Background())
	})

	// Prepare a test message
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	data, _ := m.Pack()
	msg := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(msg, uint16(len(data)))
	copy(msg[2:], data)

	// Open a TCP connection (using one to avoid client-side allocations)
	conn, err := net.DialTCP("tcp", nil, srv.LocalAddr().(*net.TCPAddr))
	require.NoError(b, err)

	// Prepare a buffer to read responses
	resBuf := make([]byte, 512)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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
	b.StopTimer()
}

func BenchmarkServeTLS(b *testing.B) {
	tlsConfig := dnsservertest.CreateServerTLSConfig("example.org")
	srv, addr, err := dnsservertest.RunLocalTLSServer(
		dnsservertest.DefaultHandler(),
		tlsConfig,
	)
	require.NoError(b, err)

	testutil.CleanupAndRequireSuccess(b, func() (err error) {
		return srv.Shutdown(context.Background())
	})

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
	for i := 0; i < b.N; i++ {
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
	b.StopTimer()
}

func BenchmarkServeHTTPS(b *testing.B) {
	proto := "https"
	tlsConfig := dnsservertest.CreateServerTLSConfig("example.org")
	srv, addr, err := dnsservertest.RunLocalHTTPSServer(
		dnsservertest.DefaultHandler(),
		tlsConfig,
		nil,
	)
	require.NoError(b, err)

	testutil.CleanupAndRequireSuccess(b, func() (err error) {
		return srv.Shutdown(context.Background())
	})

	// Prepare a test message
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	data, _ := m.Pack()
	msg := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(msg, uint16(len(data)))
	copy(msg[2:], data)

	// Prepare client
	client, err := createDoHClient(addr, tlsConfig)
	require.NoError(b, err)

	// Prepare http.Request
	req, err := createDoHRequest(proto, http.MethodPost, m)
	require.NoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var res *http.Response
		res, err = client.Do(req)
		require.NoError(b, err)

		var buf []byte
		buf, err = io.ReadAll(res.Body)
		_ = res.Body.Close()
		require.NoError(b, err)
		require.GreaterOrEqual(b, len(buf), dnsserver.DNSHeaderSize)
	}
	b.StopTimer()
}

func BenchmarkServePlainHTTP(b *testing.B) {
	proto := "http"
	srv, addr, err := dnsservertest.RunLocalHTTPSServer(
		dnsservertest.DefaultHandler(),
		nil,
		nil,
	)
	require.NoError(b, err)

	testutil.CleanupAndRequireSuccess(b, func() (err error) {
		return srv.Shutdown(context.Background())
	})

	// Prepare a test message
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	data, _ := m.Pack()
	msg := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(msg, uint16(len(data)))
	copy(msg[2:], data)

	// Prepare client
	client, err := createDoHClient(addr, nil)
	require.NoError(b, err)

	// Prepare http.Request
	req, err := createDoHRequest(proto, http.MethodPost, m)
	require.NoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var res *http.Response
		res, err = client.Do(req)
		require.NoError(b, err)

		var buf []byte
		buf, err = io.ReadAll(res.Body)
		_ = res.Body.Close()
		require.NoError(b, err)
		require.GreaterOrEqual(b, len(buf), dnsserver.DNSHeaderSize)
	}
	b.StopTimer()
}

func BenchmarkServeDNSCryptUDP(b *testing.B) {
	benchmarkServeDNSCrypt(b, dnsserver.NetworkUDP)
}

func BenchmarkServeDNSCryptTCP(b *testing.B) {
	benchmarkServeDNSCrypt(b, dnsserver.NetworkTCP)
}

func BenchmarkServeQUIC(b *testing.B) {
	tlsConfig := dnsservertest.CreateServerTLSConfig("example.org")
	srv, addr, err := dnsservertest.RunLocalQUICServer(
		dnsservertest.DefaultHandler(),
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
	sess, err := quic.DialAddr(addr.String(), tlsConfig, nil)
	require.NoError(b, err)
	defer func() {
		err = sess.CloseWithError(0, "")
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var resp *dns.Msg
		resp, err = sendQUICMessage(sess, req, false)
		require.NoError(b, err)
		require.NotNil(b, resp)
		require.True(b, resp.Response)
	}
	b.StopTimer()
}

func benchmarkServeDNSCrypt(b *testing.B, network dnsserver.Network) {
	s, err := dnsservertest.RunLocalDNSCryptServer(
		dnsservertest.DefaultHandler(),
		network,
	)
	require.NoError(b, err)
	b.Cleanup(func() {
		err = s.Srv.Shutdown(context.Background())
		require.NoError(b, err)
	})

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
		Net:     string(network),
	}

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
	conn, err := net.Dial(string(network), stamp.ServerAddrStr)
	require.NoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var resp *dns.Msg
		resp, err = client.ExchangeConn(conn, req, ri)
		require.NoError(b, err)
		require.True(b, resp.Response)
	}
	b.StopTimer()
}
