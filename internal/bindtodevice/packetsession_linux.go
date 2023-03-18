//go:build linux

package bindtodevice

import (
	"net"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
)

// packetSession is a [netext.PacketSession] that contains additional
// information about the packet read from a UDP connection that has the
// SO_BINDTODEVICE option set.
type packetSession struct {
	laddr    *net.UDPAddr
	raddr    *net.UDPAddr
	readBody []byte
	respOOB  []byte
}

// type check
var _ netext.PacketSession = (*packetSession)(nil)

// LocalAddr implements the [netext.PacketSession] interface for *packetSession.
func (s *packetSession) LocalAddr() (addr net.Addr) { return s.laddr }

// RemoteAddr implements the [netext.PacketSession] interface for
// *packetSession.
func (s *packetSession) RemoteAddr() (addr net.Addr) { return s.raddr }
