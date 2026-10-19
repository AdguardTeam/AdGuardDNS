//go:build linux

package bindtodevice

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestInterfaceEnvVarName is the environment variable name the presence and
// value of which define whether to run the SO_BINDTODEVICE tests and on which
// network interface.
const TestInterfaceEnvVarName = "ADGUARD_DNS_TEST_NET_INTERFACE"

// InterfaceForTests returns the network interface designated for tests, if
// any, as well as its first network.
func InterfaceForTests(t testing.TB) (iface *net.Interface, ifaceNet *net.IPNet) {
	t.Helper()

	ifaceName, ok := os.LookupEnv(TestInterfaceEnvVarName)
	if !ok {
		return nil, nil
	}

	iface, err := net.InterfaceByName(ifaceName)
	require.NoError(t, err)

	reqAddrs, err := iface.Addrs()
	require.NoError(t, err)
	require.NotEmpty(t, reqAddrs)

	ifaceNet = testutil.RequireTypeAssert[*net.IPNet](t, reqAddrs[0])
	masked := &net.IPNet{
		IP:   ifaceNet.IP.Mask(ifaceNet.Mask),
		Mask: ifaceNet.Mask,
	}
	t.Logf(
		"assuming following command has been called:\n"+
			"ip route add local %[1]s dev %[2]s\n"+
			"after the test:\n"+
			"ip route del local %[1]s dev %[2]s",
		masked,
		ifaceName,
	)

	return iface, ifaceNet
}

func TestIPDstOOBSize(t *testing.T) {
	len4 := unix.CmsgSpace(int(unsafe.Sizeof(unix.RawSockaddrInet4{})))
	len6 := unix.CmsgSpace(int(unsafe.Sizeof(unix.RawSockaddrInet6{})))

	assert.Equal(t, max(len4, len6), IPDstOOBSize)
}

// TestListenControl checks the SO_BINDTODEVICE handling.  The test assumes that
// the correct routing has already been set up on the machine.  To test the
// package an actual network interface is required.  To set that up:
//
//  1. Run ip a to locate the interface you want to use and its subnet.  For
//     example, "wlp3s0" and "192.168.10.0/23".
//
//  2. Add a route for that interface: "ip route add local 192.168.10.0/23 dev
//     wlp3s0".  You might need sudo for that.
//
//  3. Run the test itself: "env ADGUARD_DNS_TEST_NET_INTERFACE='wlp3s0' go test
//     -v ./internal/bindtodevice/".
//
//  4. Delete the route you added in step 2: "ip route del local 192.168.10.0/23
//     dev wlp3s0".  You might need sudo for that.
//
// An all-in-one example, with sudo:
//
//	sudo ip route add local 192.168.10.0/23 dev wlp3s0\
//		; env ADGUARD_DNS_TEST_NET_INTERFACE='wlp3s0'\
//			go test ./internal/bindtodevice/\
//		; sudo ip route del local 192.168.10.0/23 dev wlp3s0
func TestListenControl(t *testing.T) {
	iface, ifaceNet := InterfaceForTests(t)
	if iface == nil {
		t.Skipf("test %s skipped: please set env var %s", t.Name(), TestInterfaceEnvVarName)
	}

	ifaceName := iface.Name
	lc := newListenConfig(ifaceName, &ControlConfig{})
	require.NotNil(t, lc)

	t.Run("udp", func(t *testing.T) {
		SubtestListenControlUDP(t, lc, ifaceName, ifaceNet)
	})

	t.Run("tcp", func(t *testing.T) {
		SubtestListenControlTCP(t, lc, ifaceName, ifaceNet)
	})

	t.Run("tls", func(t *testing.T) {
		SubtestListenControlTLS(t, lc, ifaceName, ifaceNet)
	})

	t.Run("doh", func(t *testing.T) {
		SubtestListenControlHTTPS(t, lc, ifaceName, ifaceNet)
	})

	t.Run("doh3", func(t *testing.T) {
		SubtestListenControlDoH3(t, lc, ifaceName, ifaceNet)
	})

	t.Run("quic", func(t *testing.T) {
		SubtestListenControlQUIC(t, lc, ifaceName, ifaceNet)
	})
}

// SubtestListenControlTCP is a shared subtest that uses lc to dial a listener
// and perform two-way communication using the resulting connection.
func SubtestListenControlTCP(
	t *testing.T,
	lc netext.ListenConfig,
	ifaceName string,
	ifaceNet *net.IPNet,
) {
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	lsnr, err := lc.Listen(ctx, "tcp", "0.0.0.0:0")
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, lsnr.Close)

	// Make sure we can work with [agdnet.PrefixNetAddr] as well.
	addrStr, _, _ := strings.Cut(lsnr.Addr().String(), "/")
	addr, err := netip.ParseAddrPort(addrStr)
	require.NoError(t, err)

	addrPort := int(addr.Port())
	ifaceAddr := &net.TCPAddr{
		IP:   ifaceNet.IP,
		Port: addrPort,
	}

	normalize(ifaceAddr)

	t.Run("main_interface_addr", func(t *testing.T) {
		t.Logf("using addr %s for iface %s", ifaceAddr, ifaceName)

		testListenControlTCPQuery(t, lsnr, ifaceAddr)
	})

	t.Run("other_interface_addr", func(t *testing.T) {
		otherIfaceAddr := &net.TCPAddr{
			IP:   closestIP(t, ifaceNet, ifaceAddr.IP),
			Port: ifaceAddr.Port,
		}

		normalize(otherIfaceAddr)

		t.Logf("using addr %s for iface %s", otherIfaceAddr, ifaceName)

		testListenControlTCPQuery(t, lsnr, otherIfaceAddr)
	})
}

func testListenControlTCPQuery(t *testing.T, lsnr net.Listener, reqAddr *net.TCPAddr) {
	t.Helper()

	req, resp := []byte("hello"), []byte("world")

	go requestTCP(reqAddr, slices.Clone(req), slices.Clone(resp))

	localConn, err := lsnr.Accept()
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, localConn.Close)

	exchangeLocal(t, localConn, reqAddr, req, resp)
}

// SubtestListenControlUDP is a shared subtest that uses lc to dial a packet
// connection and perform two-way communication with it.
func SubtestListenControlUDP(
	t *testing.T,
	lc netext.ListenConfig,
	ifaceName string,
	ifaceNet *net.IPNet,
) {
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	packetConn, err := lc.ListenPacket(ctx, "udp", "0.0.0.0:0")
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, packetConn.Close)

	// Make sure we can work with [agdnet.PrefixNetAddr] as well.
	addrStr, _, _ := strings.Cut(packetConn.LocalAddr().String(), "/")
	addr, err := netip.ParseAddrPort(addrStr)
	require.NoError(t, err)

	addrPort := int(addr.Port())
	ifaceAddr := &net.UDPAddr{
		IP:   ifaceNet.IP,
		Port: addrPort,
	}

	normalize(ifaceAddr)

	t.Run("main_interface_addr", func(t *testing.T) {
		t.Logf("using addr %s for iface %s", ifaceAddr, ifaceName)

		testListenControlUDPQuery(t, packetConn, ifaceAddr)
	})

	t.Run("other_interface_addr", func(t *testing.T) {
		otherIfaceAddr := &net.UDPAddr{
			IP:   closestIP(t, ifaceNet, ifaceAddr.IP),
			Port: ifaceAddr.Port,
		}

		normalize(otherIfaceAddr)

		t.Logf("using addr %s for iface %s", otherIfaceAddr, ifaceName)

		testListenControlUDPQuery(t, packetConn, otherIfaceAddr)
	})
}

func testListenControlUDPQuery(t *testing.T, packetConn net.PacketConn, reqAddr *net.UDPAddr) {
	t.Helper()

	req, resp := []byte("hello"), []byte("world")
	reqLen, respLen := len(req), len(resp)

	go requestUDP(reqAddr, slices.Clone(req), slices.Clone(resp))

	err := packetConn.SetReadDeadline(time.Now().Add(testTimeout))
	require.NoError(t, err)

	b := make([]byte, reqLen)
	oob := make([]byte, IPDstOOBSize)

	var sess *packetSession
	switch c := packetConn.(type) {
	case *net.UDPConn:
		sess, err = readPacketSession(c, &b, oob)
		require.NoError(t, err)
	case netext.SessionPacketConn:
		var s netext.PacketSession
		_, s, err = c.ReadFromSession(req)
		require.NoError(t, err)

		sess = testutil.RequireTypeAssert[*packetSession](t, s)
		require.NotNil(t, sess)
	default:
		t.Fatalf("bad packet conn type %T(%[1]v)", c)
	}

	assert.Equal(t, reqAddr, sess.laddr)
	assert.Equal(t, 0, sess.flags)

	err = packetConn.SetWriteDeadline(time.Now().Add(testTimeout))
	require.NoError(t, err)

	var n int
	switch c := packetConn.(type) {
	case *net.UDPConn:
		n, _, err = c.WriteMsgUDP(resp, sess.respOOB, sess.raddr)
		require.NoError(t, err)
	case netext.SessionPacketConn:
		n, err = c.WriteToSession(resp, sess)
		require.NoError(t, err)
	}

	assert.Equal(t, respLen, n)
}

// SubtestListenControlTLS is a shared subtest that uses lc to dial a TLS
// listener and perform two-way communication using the resulting connection.
// lc, ifaceNet must not be nil.
func SubtestListenControlTLS(
	t *testing.T,
	lc netext.ListenConfig,
	ifaceName string,
	ifaceNet *net.IPNet,
) {
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	lsnr, err := lc.Listen(ctx, "tcp", "0.0.0.0:0")
	require.NoError(t, err)

	serverConf := dnsservertest.NewTLSConfig(dnsservertest.DomainName, time.Time{})
	tlsLsnr := tls.NewListener(lsnr, serverConf)
	testutil.CleanupAndRequireSuccess(t, tlsLsnr.Close)

	// Make sure we can work with [agdnet.PrefixNetAddr] as well.
	addrStr, _, _ := strings.Cut(lsnr.Addr().String(), "/")
	addr, err := netip.ParseAddrPort(addrStr)
	require.NoError(t, err)

	ifaceAddr := &net.TCPAddr{
		IP:   ifaceNet.IP,
		Port: int(addr.Port()),
	}
	normalize(ifaceAddr)

	t.Run("main_interface_addr", func(t *testing.T) {
		t.Logf("using addr %s for iface %s", ifaceAddr, ifaceName)

		testListenControlTLSQuery(t, tlsLsnr, serverConf.RootCAs, ifaceAddr)
	})

	t.Run("other_interface_addr", func(t *testing.T) {
		otherIfaceAddr := &net.TCPAddr{
			IP:   closestIP(t, ifaceNet, ifaceAddr.IP),
			Port: ifaceAddr.Port,
		}
		normalize(otherIfaceAddr)

		t.Logf("using addr %s for iface %s", otherIfaceAddr, ifaceName)

		testListenControlTLSQuery(t, tlsLsnr, serverConf.RootCAs, otherIfaceAddr)
	})
}

// testListenControlTLSQuery is a helper that uses lsnr to make a TLS handshake
// and to establish communication.  lsnr, roots, and reqAddr must not be nil.
func testListenControlTLSQuery(
	t *testing.T,
	lsnr net.Listener,
	roots *x509.CertPool,
	reqAddr *net.TCPAddr,
) {
	t.Helper()

	req, resp := []byte("hello"), []byte("world")

	go requestTLS(reqAddr, roots, slices.Clone(req), slices.Clone(resp))

	localConn, err := lsnr.Accept()
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, localConn.Close)

	tlsConn := testutil.RequireTypeAssert[*tls.Conn](t, localConn)
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	err = tlsConn.HandshakeContext(ctx)
	require.NoError(t, err)

	exchangeLocal(t, localConn, reqAddr, req, resp)
}

// SubtestListenControlHTTPS is a shared subtest that uses lc to serve DoH over
// HTTP/1.1-2 and perform a request using the resulting connection.  lc,
// ifaceNet must not be nil.
func SubtestListenControlHTTPS(
	t *testing.T,
	lc netext.ListenConfig,
	ifaceName string,
	ifaceNet *net.IPNet,
) {
	req, resp := []byte("hello"), []byte("world")

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	lsnr, err := lc.Listen(ctx, "tcp", "0.0.0.0:0")
	require.NoError(t, err)

	serverConf := dnsservertest.NewTLSConfig(dnsservertest.DomainName, time.Time{})
	serverConf.NextProtos = []string{"h2", "http/1.1"}
	tlsLsnr := tls.NewListener(lsnr, serverConf)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		pt := testutil.NewPanicT(t)

		wantReqLen := len(req)

		gotReq := make([]byte, wantReqLen)
		n, rErr := io.ReadFull(r.Body, gotReq)
		require.NoError(pt, rErr)

		assert.Equal(pt, wantReqLen, n)
		assert.Equal(pt, req, gotReq)

		n, wErr := w.Write(resp)
		require.NoError(pt, wErr)

		assert.Equal(pt, len(resp), n)
	})

	srv := &http.Server{
		Handler:           mux,
		ReadTimeout:       testTimeout,
		ReadHeaderTimeout: testTimeout,
		WriteTimeout:      testTimeout,
		IdleTimeout:       testTimeout,
	}
	testutil.CleanupAndRequireSuccess(t, srv.Close)

	go func() {
		cErr := srv.Serve(tlsLsnr)
		require.ErrorIs(testutil.NewPanicT(t), cErr, http.ErrServerClosed)
	}()

	// Make sure we can work with [agdnet.PrefixNetAddr] as well.
	addrStr, _, _ := strings.Cut(lsnr.Addr().String(), "/")
	addr, err := netip.ParseAddrPort(addrStr)
	require.NoError(t, err)

	ifaceAddr := &net.TCPAddr{
		IP:   ifaceNet.IP,
		Port: int(addr.Port()),
	}
	normalize(ifaceAddr)

	t.Run("main_interface_addr", func(t *testing.T) {
		t.Logf("using addr %s for iface %s", ifaceAddr, ifaceName)

		testListenControlHTTPSQuery(t, serverConf.RootCAs, ifaceAddr, req, resp)
	})

	t.Run("other_interface_addr", func(t *testing.T) {
		otherIfaceAddr := &net.TCPAddr{
			IP:   closestIP(t, ifaceNet, ifaceAddr.IP),
			Port: ifaceAddr.Port,
		}
		normalize(otherIfaceAddr)

		t.Logf("using addr %s for iface %s", otherIfaceAddr, ifaceName)

		testListenControlHTTPSQuery(t, serverConf.RootCAs, otherIfaceAddr, req, resp)
	})
}

// testListenControlHTTPSQuery is a helper that makes a DoH request to reqAddr.
// roots and reqAddr must not be nil.
func testListenControlHTTPSQuery(
	t *testing.T,
	roots *x509.CertPool,
	reqAddr *net.TCPAddr,
	req []byte,
	wantResp []byte,
) {
	t.Helper()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: dnsservertest.DomainName,
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   testTimeout,
	}

	u := &url.URL{
		Scheme: urlutil.SchemeHTTPS,
		Host:   reqAddr.String(),
		Path:   "/",
	}

	resp, err := client.Post(u.String(), "application/octet-stream", bytes.NewReader(req))
	require.NoError(t, err)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, wantResp, b)
}

// SubtestListenControlQUIC is a shared subtest that uses lc to serve QUIC and
// perform two-way communication using the resulting connection.  lc, ifaceNet
// must not be nil.
func SubtestListenControlQUIC(
	t *testing.T,
	lc netext.ListenConfig,
	ifaceName string,
	ifaceNet *net.IPNet,
) {
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	packetConn, err := lc.ListenPacket(ctx, "udp", "0.0.0.0:0")
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, packetConn.Close)

	serverConf := dnsservertest.NewTLSConfig(dnsservertest.DomainName, time.Time{})
	serverConf.NextProtos = dnsserver.NextProtoDoQ
	transport := &quic.Transport{
		Conn: packetConn,
	}
	testutil.CleanupAndRequireSuccess(t, transport.Close)

	lsnr, err := transport.Listen(serverConf, nil)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, lsnr.Close)

	// Make sure we can work with [agdnet.PrefixNetAddr] as well.
	addrStr, _, _ := strings.Cut(packetConn.LocalAddr().String(), "/")
	addr, err := netip.ParseAddrPort(addrStr)
	require.NoError(t, err)

	ifaceAddr := &net.UDPAddr{
		IP:   ifaceNet.IP,
		Port: int(addr.Port()),
	}

	normalize(ifaceAddr)

	t.Run("main_interface_addr", func(t *testing.T) {
		t.Logf("using addr %s for iface %s", ifaceAddr, ifaceName)

		testListenControlQUICQuery(t, lsnr, serverConf, ifaceAddr)
	})

	t.Run("other_interface_addr", func(t *testing.T) {
		otherIfaceAddr := &net.UDPAddr{
			IP:   closestIP(t, ifaceNet, ifaceAddr.IP),
			Port: ifaceAddr.Port,
		}

		normalize(otherIfaceAddr)

		t.Logf("using addr %s for iface %s", otherIfaceAddr, ifaceName)

		testListenControlQUICQuery(t, lsnr, serverConf, otherIfaceAddr)
	})
}

// testListenControlQUICQuery is a helper that uses lsnr to make a QUIC
// handshake and to establish communication.  lsnr, tlsConf, and reqAddr must
// not be nil.
func testListenControlQUICQuery(
	tb testing.TB,
	lsnr *quic.Listener,
	tlsConf *tls.Config,
	reqAddr *net.UDPAddr,
) {
	tb.Helper()

	req, resp := []byte("hello"), []byte("world")
	clientDone := make(chan unit)

	ctx := testutil.ContextWithTimeout(tb, testTimeout)
	go requestQUIC(tb, reqAddr, tlsConf, slices.Clone(req), slices.Clone(resp), clientDone)
	defer testutil.RequireReceive(tb, clientDone, testTimeout)

	conn, err := lsnr.Accept(ctx)
	require.NoError(tb, err)
	testutil.CleanupAndRequireSuccess(tb, func() (err error) {
		return conn.CloseWithError(0, "")
	})

	stream, err := conn.AcceptStream(ctx)
	require.NoError(tb, err)
	testutil.CleanupAndRequireSuccess(tb, stream.Close)

	err = stream.SetDeadline(time.Now().Add(testTimeout))
	require.NoError(tb, err)

	gotReq := make([]byte, len(req))
	n, err := io.ReadFull(stream, gotReq)
	require.NoError(tb, err)

	assert.Equal(tb, len(req), n)
	assert.Equal(tb, req, gotReq)

	n, err = stream.Write(resp)
	require.NoError(tb, err)

	assert.Equal(tb, len(resp), n)
}

// requestQUIC is a test helper that dials raddr over QUIC, completes the
// handshake, and establishes communication.  It is intended to be used as a
// goroutine.  raddr, tlsConf, and done must not be nil.
func requestQUIC(
	tb testing.TB,
	raddr *net.UDPAddr,
	tlsConf *tls.Config,
	req []byte,
	wantResp []byte,
	done chan<- unit,
) {
	pt := testutil.NewPanicT(tb)
	defer close(done)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	clientConf := tlsConf.Clone()
	clientConf.Certificates = nil

	conn, err := quic.DialAddr(ctx, raddr.String(), clientConf, nil)
	require.NoError(pt, err)
	defer func() {
		closeErr := conn.CloseWithError(0, "")
		require.NoError(pt, closeErr)
	}()

	stream, err := conn.OpenStreamSync(ctx)
	require.NoError(pt, err)
	defer func() {
		closeErr := stream.Close()
		require.NoError(pt, closeErr)
	}()

	n, err := stream.Write(req)
	require.NoError(pt, err)

	assert.Equal(pt, len(req), n)

	gotResp := make([]byte, len(wantResp))
	n, err = io.ReadFull(stream, gotResp)
	require.NoError(pt, err)

	assert.Equal(pt, len(wantResp), n)
	assert.Equal(pt, wantResp, gotResp)
}

// SubtestListenControlDoH3 is a shared subtest that uses lc to serve DoH over
// HTTP/3 and perform a request using the resulting connection.  lc, ifaceNet
// must not be nil.
func SubtestListenControlDoH3(
	t *testing.T,
	lc netext.ListenConfig,
	ifaceName string,
	ifaceNet *net.IPNet,
) {
	req, resp := []byte("hello"), []byte("world")

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	conn, err := lc.ListenPacket(ctx, "udp", "0.0.0.0:0")
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, conn.Close)

	serverConf := dnsservertest.NewTLSConfig(dnsservertest.DomainName, time.Time{})
	serverConf.NextProtos = dnsserver.NextProtoDoH3

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		pt := testutil.NewPanicT(t)
		require.Equal(pt, 3, r.ProtoMajor)

		wantReqLen := len(req)

		gotReq := make([]byte, wantReqLen)
		n, rErr := io.ReadFull(r.Body, gotReq)
		require.NoError(pt, rErr)

		assert.Equal(pt, wantReqLen, n)
		assert.Equal(pt, req, gotReq)

		n, wErr := w.Write(resp)
		require.NoError(pt, wErr)

		assert.Equal(pt, len(resp), n)
	})

	srv := &http3.Server{
		Handler:     mux,
		TLSConfig:   serverConf,
		IdleTimeout: testTimeout,
	}
	testutil.CleanupAndRequireSuccess(t, srv.Close)

	go func() {
		cErr := srv.Serve(conn)
		require.ErrorIs(testutil.NewPanicT(t), cErr, http.ErrServerClosed)
	}()

	// Make sure we can work with [agdnet.PrefixNetAddr] as well.
	addrStr, _, _ := strings.Cut(conn.LocalAddr().String(), "/")
	addr, err := netip.ParseAddrPort(addrStr)
	require.NoError(t, err)

	ifaceAddr := &net.UDPAddr{
		IP:   ifaceNet.IP,
		Port: int(addr.Port()),
	}
	normalize(ifaceAddr)

	t.Run("main_interface_addr", func(t *testing.T) {
		t.Logf("using addr %s for iface %s", ifaceAddr, ifaceName)

		testListenControlDoH3Query(t, serverConf.RootCAs, ifaceAddr, req, resp)
	})

	t.Run("other_interface_addr", func(t *testing.T) {
		otherIfaceAddr := &net.UDPAddr{
			IP:   closestIP(t, ifaceNet, ifaceAddr.IP),
			Port: ifaceAddr.Port,
		}
		normalize(otherIfaceAddr)

		t.Logf("using addr %s for iface %s", otherIfaceAddr, ifaceName)

		testListenControlDoH3Query(t, serverConf.RootCAs, otherIfaceAddr, req, resp)
	})
}

// testListenControlDoH3Query is a helper that makes a DoH3 request to reqAddr.
// roots and reqAddr must not be nil.
func testListenControlDoH3Query(
	tb testing.TB,
	roots *x509.CertPool,
	reqAddr *net.UDPAddr,
	req []byte,
	wantResp []byte,
) {
	tb.Helper()

	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: dnsservertest.DomainName,
			RootCAs:    roots,
			NextProtos: []string{http3.NextProtoH3},
			MinVersion: tls.VersionTLS13,
		},
	}
	testutil.CleanupAndRequireSuccess(tb, transport.Close)

	client := &http.Client{
		Transport: transport,
		Timeout:   testTimeout,
	}

	u := &url.URL{
		Scheme: urlutil.SchemeHTTPS,
		Host:   reqAddr.String(),
		Path:   "/",
	}

	resp, err := client.Post(u.String(), "application/octet-stream", bytes.NewReader(req))
	require.NoError(tb, err)
	defer func() {
		require.NoError(tb, resp.Body.Close())
	}()

	require.Equal(tb, http.StatusOK, resp.StatusCode)
	require.Equal(tb, 3, resp.ProtoMajor)

	b, err := io.ReadAll(resp.Body)
	require.NoError(tb, err)

	assert.Equal(tb, wantResp, b)
}

// requestTLS is a test helper that dials raddr over TLS, completes the
// handshake, and establishes communication.  It is intended to be used as a
// goroutine.  raddr and roots must not be nil.
func requestTLS(raddr *net.TCPAddr, roots *x509.CertPool, req, wantResp []byte) {
	pt := testutil.PanicT{}

	dialer := &net.Dialer{
		Timeout: testTimeout,
	}
	remoteConn, err := tls.DialWithDialer(dialer, "tcp", raddr.String(), &tls.Config{
		ServerName: dnsservertest.DomainName,
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	})
	require.NoError(pt, err)
	defer func() {
		closeErr := remoteConn.Close()
		require.NoError(pt, closeErr)
	}()

	exchangeRemote(pt, remoteConn, req, wantResp)
}

// requestTCP is a test helper for making TCP queries.  It is intended to be
// used as a goroutine.
func requestTCP(raddr *net.TCPAddr, req, wantResp []byte) {
	pt := testutil.PanicT{}

	remoteConn, err := net.DialTCP("tcp", nil, raddr)
	require.NoError(pt, err)
	defer func() {
		closeErr := remoteConn.Close()
		require.NoError(pt, closeErr)
	}()

	exchangeRemote(pt, remoteConn, req, wantResp)
}

// requestUDP is a test helper for making UDP queries.  It is intended to be
// used as a goroutine.
func requestUDP(raddr *net.UDPAddr, req, wantResp []byte) {
	pt := testutil.PanicT{}

	remoteConn, err := net.DialUDP("udp", nil, raddr)
	require.NoError(pt, err)
	defer func() {
		closeErr := remoteConn.Close()
		require.NoError(pt, closeErr)
	}()

	exchangeRemote(pt, remoteConn, req, wantResp)
}

// exchangeRemote is a test helper that performs the write and read operations
// on the given conn and asserts that the exchange was successful.
func exchangeRemote(t testutil.RequireT, conn net.Conn, req, wantResp []byte) {
	err := conn.SetWriteDeadline(time.Now().Add(testTimeout))
	require.NoError(t, err)

	n, err := conn.Write(req)
	require.NoError(t, err)

	assert.Equal(t, len(req), n)

	wantRespLen := len(wantResp)
	resp := make([]byte, wantRespLen)
	err = conn.SetReadDeadline(time.Now().Add(testTimeout))
	require.NoError(t, err)

	n, err = conn.Read(resp)
	require.NoError(t, err)

	assert.Equal(t, wantRespLen, n)
	assert.Equal(t, wantResp, resp)
}

// exchangeLocal is a test helper that performs the write and read operations
// on the given conn and asserts that the exchange was successful.  reqAddr and
// conn must not be nil.
func exchangeLocal(tb testing.TB, conn net.Conn, reqAddr *net.TCPAddr, wantReq, resp []byte) {
	tb.Helper()

	wantReqLen, respLen := len(wantReq), len(resp)

	laddr := testutil.RequireTypeAssert[*net.TCPAddr](tb, conn.LocalAddr())
	normalize(laddr)
	assert.Equal(tb, reqAddr, laddr)

	err := conn.SetReadDeadline(time.Now().Add(testTimeout))
	require.NoError(tb, err)

	gotReq := make([]byte, wantReqLen)
	n, err := conn.Read(gotReq)
	require.NoError(tb, err)

	assert.Equal(tb, wantReqLen, n)
	assert.Equal(tb, wantReq, gotReq)

	err = conn.SetWriteDeadline(time.Now().Add(testTimeout))
	require.NoError(tb, err)

	n, err = conn.Write(resp)
	require.NoError(tb, err)

	assert.Equal(tb, respLen, n)
}

// normalize sets the IP address of addr to a 4-byte version of the IP address
// if it is an IPv4 address.
func normalize(addr net.Addr) {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		ip4 := addr.IP.To4()
		if ip4 != nil {
			addr.IP = ip4
		}
	case *net.UDPAddr:
		ip4 := addr.IP.To4()
		if ip4 != nil {
			addr.IP = ip4
		}
	default:
		panic(fmt.Errorf("bad type %T", addr))
	}
}

// closestIP is a test helper that provides a closest IP address based on the
// provided IP network.
func closestIP(t testing.TB, n *net.IPNet, ip net.IP) (closest net.IP) {
	t.Helper()

	ipAddr, err := netutil.IPToAddrNoMapped(ip)
	require.NoError(t, err)

	ipNet, err := netutil.IPNetToPrefixNoMapped(n)
	require.NoError(t, err)

	nextAddr := ipAddr.Next()
	if ipNet.Contains(nextAddr) {
		return nextAddr.AsSlice()
	}

	prevAddr := ipAddr.Prev()
	if ipNet.Contains(prevAddr) {
		return prevAddr.AsSlice()
	}

	t.Fatalf("neither %s nor %s are in %s", nextAddr, prevAddr, ipNet)

	return nil
}

func TestListenControlWithSO(t *testing.T) {
	const (
		sndBufSize = 10000
		rcvBufSize = 20000
	)

	iface, _ := InterfaceForTests(t)
	if iface == nil {
		t.Skipf("test %s skipped: please set env var %s", t.Name(), TestInterfaceEnvVarName)
	}

	ifaceName := iface.Name
	lc := newListenConfig(
		ifaceName,
		&ControlConfig{
			RcvBufSize: rcvBufSize,
			SndBufSize: sndBufSize,
		},
	)
	require.NotNil(t, lc)

	// TODO(a.garipov):  Move to golibs.
	type syscallConner interface {
		SyscallConn() (c syscall.RawConn, err error)
	}

	t.Run("udp", func(t *testing.T) {
		c, err := lc.ListenPacket(context.Background(), "udp", "0.0.0.0:0")
		require.NoError(t, err)
		require.NotNil(t, c)

		scConner := testutil.RequireTypeAssert[syscallConner](t, c)

		sc, err := scConner.SyscallConn()
		require.NoError(t, err)

		err = sc.Control(func(fd uintptr) {
			val, opErr := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
			require.NoError(t, opErr)

			assert.Equal(t, sndBufSize*2, val)
		})
		require.NoError(t, err)

		err = sc.Control(func(fd uintptr) {
			val, opErr := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
			require.NoError(t, opErr)

			assert.Equal(t, rcvBufSize*2, val)
		})
		require.NoError(t, err)
	})

	t.Run("tcp", func(t *testing.T) {
		c, err := lc.Listen(context.Background(), "tcp", "0.0.0.0:0")
		require.NoError(t, err)
		require.NotNil(t, c)

		scConner := testutil.RequireTypeAssert[syscallConner](t, c)

		sc, err := scConner.SyscallConn()
		require.NoError(t, err)

		err = sc.Control(func(fd uintptr) {
			val, opErr := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
			require.NoError(t, opErr)

			assert.Equal(t, sndBufSize*2, val)
		})
		require.NoError(t, err)

		err = sc.Control(func(fd uintptr) {
			val, opErr := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
			require.NoError(t, opErr)

			assert.Equal(t, rcvBufSize*2, val)
		})
		require.NoError(t, err)
	})
}

// testMsgUDPReader is a [msgUDPReader] for tests.
type testMsgUDPReader struct {
	onReadMsgUDP func(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
}

// type check
var _ msgUDPReader = (*testMsgUDPReader)(nil)

// ReadMsgUDP implements the [msgUDPReader] interface for *testMsgUDPReader.
func (r *testMsgUDPReader) ReadMsgUDP(
	b []byte,
	oob []byte,
) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	return r.onReadMsgUDP(b, oob)
}

func BenchmarkReadPacketSession(b *testing.B) {
	bodyData := []byte("message body data")

	// TODO(a.garipov): Find a better way to pack these control messages than
	// just [binary.Write].
	oobBuf := &bytes.Buffer{}
	ctrlMsgHdr := unix.Cmsghdr{
		Len:   24,
		Level: unix.SOL_IP,
		Type:  unix.IP_ORIGDSTADDR,
	}

	err := binary.Write(oobBuf, binary.NativeEndian, ctrlMsgHdr)
	require.NoError(b, err)

	pktInfo := unix.Inet4Pktinfo{
		Spec_dst: *(*[4]byte)(testRAddr.IP),
		Addr:     *(*[4]byte)(testRAddr.IP),
	}

	err = binary.Write(oobBuf, binary.NativeEndian, pktInfo)
	require.NoError(b, err)

	oobData := oobBuf.Bytes()

	c := &testMsgUDPReader{
		onReadMsgUDP: func(body, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
			copy(body, bodyData)
			copy(oob, oobData)

			return len(bodyData), len(oobData), 0, testRAddr, nil
		},
	}

	body := make([]byte, dns.DefaultMsgSize)
	oob := make([]byte, IPDstOOBSize)

	var sess *packetSession

	b.ReportAllocs()
	for b.Loop() {
		sess, err = readPacketSession(c, &body, oob)
	}

	require.NoError(b, err)
	require.NotNil(b, sess)
	require.NotNil(b, sess.readBodyPtr)

	assert.Equal(b, sess.raddr, testRAddr)
	assert.Equal(b, *sess.readBodyPtr, bodyData)

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice
	//	cpu: AMD Ryzen AI 9 HX PRO 370 w/ Radeon 890M
	//	BenchmarkReadPacketSession-24    	 8371399	       128.2 ns/op	     224 B/op	       5 allocs/op
}
