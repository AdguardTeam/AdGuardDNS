//go:build linux

// TODO(a.garipov): Technically, we can expand this to other platforms, but that
// would require separate udpOOBSize constants and tests.

package netext

import (
	"fmt"
	"net"

	"github.com/AdguardTeam/golibs/syncutil"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// type check
var _ PacketSession = (*packetSession)(nil)

// packetSession contains additional information about the packet read from a
// UDP connection.  It is basically an extended version of [dns.SessionUDP] that
// contains the local address as well.
type packetSession struct {
	laddr   *net.UDPAddr
	raddr   *net.UDPAddr
	respOOB []byte
}

// LocalAddr implements the [PacketSession] interface for *packetSession.
func (s *packetSession) LocalAddr() (addr net.Addr) { return s.laddr }

// RemoteAddr implements the [PacketSession] interface for *packetSession.
func (s *packetSession) RemoteAddr() (addr net.Addr) { return s.raddr }

// type check
var _ SessionPacketConn = (*sessionPacketConn)(nil)

// wrapPacketConn wraps c to make it a [SessionPacketConn], if the OS supports
// that.
func wrapPacketConn(c net.PacketConn) (wrapped net.PacketConn) {
	return &sessionPacketConn{
		UDPConn: *c.(*net.UDPConn),
	}
}

// sessionPacketConn wraps a UDP connection and implements [SessionPacketConn].
type sessionPacketConn struct {
	net.UDPConn
}

// oobPool is the pool of byte slices for out-of-band data.
var oobPool = syncutil.NewSlicePool[byte](IPDstOOBSize)

// IPDstOOBSize is the required size of the control-message buffer for
// [net.UDPConn.ReadMsgUDP] to read the original destination on Linux.
//
// See packetconn_linux_internal_test.go.
const IPDstOOBSize = 40

// ReadFromSession implements the [SessionPacketConn] interface for *packetConn.
func (c *sessionPacketConn) ReadFromSession(b []byte) (n int, s PacketSession, err error) {
	oobPtr := oobPool.Get()
	defer oobPool.Put(oobPtr)

	var oobn int
	oob := *oobPtr
	ps := &packetSession{}
	n, oobn, _, ps.raddr, err = c.ReadMsgUDP(b, oob)
	if err != nil {
		return 0, nil, err
	}

	var origDstIP net.IP
	sockLAddr := c.LocalAddr().(*net.UDPAddr)
	origDstIP, err = origLAddr(oob[:oobn])
	if err != nil {
		return 0, nil, fmt.Errorf("getting original addr: %w", err)
	}

	if origDstIP == nil {
		ps.laddr = sockLAddr
	} else {
		ps.respOOB = newRespOOB(origDstIP)
		ps.laddr = &net.UDPAddr{
			IP:   origDstIP,
			Port: sockLAddr.Port,
		}
	}

	return n, ps, nil
}

// origLAddr returns the original local address from the encoded control-message
// data, if there is one.  If not nil, origDst will have a protocol-appropriate
// length.
func origLAddr(oob []byte) (origDst net.IP, err error) {
	ctrlMsg6 := &ipv6.ControlMessage{}
	err = ctrlMsg6.Parse(oob)
	if err != nil {
		return nil, fmt.Errorf("parsing ipv6 control message: %w", err)
	}

	if dst := ctrlMsg6.Dst; dst != nil {
		// Linux maps IPv4 addresses to IPv6 ones by default, so we can get an
		// IPv4 dst from an IPv6 control-message.
		origDst = dst.To4()
		if origDst == nil {
			origDst = dst
		}

		return origDst, nil
	}

	ctrlMsg4 := &ipv4.ControlMessage{}
	err = ctrlMsg4.Parse(oob)
	if err != nil {
		return nil, fmt.Errorf("parsing ipv4 control message: %w", err)
	}

	return ctrlMsg4.Dst.To4(), nil
}

// newRespOOB returns an encoded control-message for the response for this IP
// address.  origDst is expected to have a protocol-appropriate length.
func newRespOOB(origDst net.IP) (b []byte) {
	switch len(origDst) {
	case net.IPv4len:
		cm := &ipv4.ControlMessage{
			Src: origDst,
		}

		return cm.Marshal()
	case net.IPv6len:
		cm := &ipv6.ControlMessage{
			Src: origDst,
		}

		return cm.Marshal()
	default:
		return nil
	}
}

// WriteToSession implements the [SessionPacketConn] interface for *packetConn.
func (c *sessionPacketConn) WriteToSession(b []byte, s PacketSession) (n int, err error) {
	if ps, ok := s.(*packetSession); ok {
		n, _, err = c.WriteMsgUDP(b, ps.respOOB, ps.raddr)

		return n, err
	}

	return c.WriteTo(b, s.RemoteAddr())
}
