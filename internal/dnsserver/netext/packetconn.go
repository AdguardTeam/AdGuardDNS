package netext

import (
	"net"
)

// PacketSession contains additional information about a packet read from or
// written to a [SessionPacketConn].
type PacketSession interface {
	LocalAddr() (addr net.Addr)
	RemoteAddr() (addr net.Addr)
}

// NewSimplePacketSession returns a new packet session using the given
// parameters.
func NewSimplePacketSession(laddr, raddr net.Addr) (s PacketSession) {
	return &simplePacketSession{
		laddr: laddr,
		raddr: raddr,
	}
}

// simplePacketSession is a simple implementation of the [PacketSession]
// interface.
type simplePacketSession struct {
	laddr net.Addr
	raddr net.Addr
}

// LocalAddr implements the [PacketSession] interface for *simplePacketSession.
func (s *simplePacketSession) LocalAddr() (addr net.Addr) { return s.laddr }

// RemoteAddr implements the [PacketSession] interface for *simplePacketSession.
func (s *simplePacketSession) RemoteAddr() (addr net.Addr) { return s.raddr }

// SessionPacketConn extends [net.PacketConn] with methods for working with
// packet sessions.
type SessionPacketConn interface {
	net.PacketConn

	ReadFromSession(b []byte) (n int, s PacketSession, err error)
	WriteToSession(b []byte, s PacketSession) (n int, err error)
}

// ReadFromSession is a convenience wrapper for types that may or may not
// implement [SessionPacketConn].  If c implements it, ReadFromSession uses
// c.ReadFromSession.  Otherwise, it uses c.ReadFrom and the session is created
// by using [NewSimplePacketSession] with c.LocalAddr.
func ReadFromSession(c net.PacketConn, b []byte) (n int, s PacketSession, err error) {
	if spc, ok := c.(SessionPacketConn); ok {
		return spc.ReadFromSession(b)
	}

	n, raddr, err := c.ReadFrom(b)
	s = NewSimplePacketSession(c.LocalAddr(), raddr)

	return n, s, err
}

// WriteToSession is a convenience wrapper for types that may or may not
// implement [SessionPacketConn].  If c implements it, WriteToSession uses
// c.WriteToSession.  Otherwise, it uses c.WriteTo using s.RemoteAddr.
func WriteToSession(c net.PacketConn, b []byte, s PacketSession) (n int, err error) {
	if spc, ok := c.(SessionPacketConn); ok {
		return spc.WriteToSession(b, s)
	}

	return c.WriteTo(b, s.RemoteAddr())
}
