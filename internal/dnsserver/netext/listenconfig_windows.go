//go:build windows

package netext

import (
	"net"
	"syscall"
)

// defaultListenControl is nil on Windows, because it doesn't support
// SO_REUSEPORT.
var defaultListenControl func(_, _ string, _ syscall.RawConn) (_ error)

// setIPOpts sets the IPv4 and IPv6 options on a packet connection.
func setIPOpts(c net.PacketConn) (err error) {
	return nil
}
