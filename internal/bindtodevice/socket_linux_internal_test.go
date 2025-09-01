//go:build linux

package bindtodevice

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
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

	t.Run("tcp", func(t *testing.T) {
		SubtestListenControlTCP(t, lc, ifaceName, ifaceNet)
	})

	t.Run("udp", func(t *testing.T) {
		SubtestListenControlUDP(t, lc, ifaceName, ifaceNet)
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
	req, resp := []byte("hello"), []byte("world")
	reqLen, respLen := len(req), len(resp)

	go requestTCP(reqAddr, slices.Clone(req), slices.Clone(resp))

	localConn, err := lsnr.Accept()
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, localConn.Close)

	laddr := testutil.RequireTypeAssert[*net.TCPAddr](t, localConn.LocalAddr())
	normalize(laddr)
	assert.Equal(t, reqAddr, laddr)

	err = localConn.SetReadDeadline(time.Now().Add(testTimeout))
	require.NoError(t, err)

	gotReq := make([]byte, reqLen)
	n, err := localConn.Read(gotReq)
	require.NoError(t, err)

	assert.Equal(t, reqLen, n)
	assert.Equal(t, req, gotReq)

	err = localConn.SetWriteDeadline(time.Now().Add(testTimeout))
	require.NoError(t, err)

	n, err = localConn.Write(resp)
	require.NoError(t, err)

	assert.Equal(t, respLen, n)
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
	req, resp := []byte("hello"), []byte("world")
	reqLen, respLen := len(req), len(resp)

	go requestUDP(reqAddr, slices.Clone(req), slices.Clone(resp))

	err := packetConn.SetReadDeadline(time.Now().Add(testTimeout))
	require.NoError(t, err)

	b := make([]byte, reqLen)
	oob := make([]byte, netext.IPDstOOBSize)

	var sess *packetSession
	switch c := packetConn.(type) {
	case *net.UDPConn:
		sess, err = readPacketSession(c, b, oob)
		require.NoError(t, err)
	case netext.SessionPacketConn:
		var s netext.PacketSession
		_, s, err = c.ReadFromSession(req)
		require.NoError(t, err)

		sess = testutil.RequireTypeAssert[*packetSession](t, s)
	default:
		t.Fatalf("bad packet conn type %T(%[1]v)", c)
	}

	assert.Equal(t, reqAddr, sess.laddr)
	assert.Equal(t, req, sess.readBody)

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

	err = remoteConn.SetWriteDeadline(time.Now().Add(testTimeout))
	require.NoError(pt, err)

	n, err := remoteConn.Write(req)
	require.NoError(pt, err)

	assert.Equal(pt, len(req), n)

	wantRespLen := len(wantResp)
	resp := make([]byte, wantRespLen)
	err = remoteConn.SetReadDeadline(time.Now().Add(testTimeout))
	require.NoError(pt, err)

	n, err = remoteConn.Read(resp)
	require.NoError(pt, err)

	assert.Equal(pt, wantRespLen, n)
	assert.Equal(pt, wantResp, resp)
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

	err = remoteConn.SetWriteDeadline(time.Now().Add(testTimeout))
	require.NoError(pt, err)

	n, err := remoteConn.Write(req)
	require.NoError(pt, err)

	assert.Equal(pt, len(req), n)

	wantRespLen := len(wantResp)
	resp := make([]byte, wantRespLen)
	err = remoteConn.SetReadDeadline(time.Now().Add(testTimeout))
	require.NoError(pt, err)

	n, err = remoteConn.Read(resp)
	require.NoError(pt, err)

	assert.Equal(pt, wantRespLen, n)
	assert.Equal(pt, wantResp, resp)
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
	oob := make([]byte, netext.IPDstOOBSize)

	var sess *packetSession

	b.ReportAllocs()
	for b.Loop() {
		sess, err = readPacketSession(c, body, oob)
	}

	require.NoError(b, err)

	require.NotNil(b, sess)
	assert.Equal(b, sess.raddr, testRAddr)
	assert.Equal(b, sess.readBody, bodyData)

	// Most recent results:
	//
	// goos: linux
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice
	// cpu: Intel(R) Core(TM) i7-10510U CPU @ 1.80GHz
	// BenchmarkReadPacketSession-8   	 7064631	       178.6 ns/op	     224 B/op	       5 allocs/op
}
