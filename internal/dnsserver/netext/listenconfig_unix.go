//go:build unix

package netext

import (
	"fmt"
	"net"
	"syscall"

	"github.com/AdguardTeam/golibs/errors"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// defaultListenControl is used as a [net.ListenConfig.Control] function to set
// the SO_REUSEPORT socket option on all sockets used by the DNS servers in this
// package.
func defaultListenControl(_, _ string, c syscall.RawConn) (err error) {
	var opErr error
	err = c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}

	return errors.WithDeferred(opErr, err)
}

// setIPOpts sets the IPv4 and IPv6 options on a packet connection.
func setIPOpts(c net.PacketConn) (err error) {
	// TODO(a.garipov): Returning an error only if both functions return one
	// (which is what module dns does as well) seems rather fragile.  Depending
	// on the OS, the valid errors are ENOPROTOOPT, EINVAL, and maybe others.
	// Investigate and make OS-specific versions to make sure we don't miss any
	// real errors.
	err6 := ipv6.NewPacketConn(c).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	err4 := ipv4.NewPacketConn(c).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
	if err4 != nil && err6 != nil {
		return fmt.Errorf("setting ipv4 and ipv6 options: %w", errors.Join(err4, err6))
	}

	return nil
}
