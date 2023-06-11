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

// setSockOptFunc is a function that sets a socket option on fd.
type setSockOptFunc func(fd int) (err error)

// newSetSockOptFunc returns a socket-option function with the given parameters.
func newSetSockOptFunc(name string, lvl, opt, val int) (o setSockOptFunc) {
	return func(fd int) (err error) {
		err = unix.SetsockoptInt(fd, lvl, opt, val)

		return errors.Annotate(err, "setting %s: %w", name)
	}
}

// listenControlWithSO is used as a [net.ListenConfig.Control] function to set
// the SO_REUSEPORT, SO_SNDBUF, and SO_RCVBUF socket options on all sockets
// used by the DNS servers in this package.  conf must not be nil.
func listenControlWithSO(conf *ControlConfig, c syscall.RawConn) (err error) {
	opts := []setSockOptFunc{
		newSetSockOptFunc("SO_REUSEPORT", unix.SOL_SOCKET, unix.SO_REUSEPORT, 1),
	}

	if conf.SndBufSize > 0 {
		opts = append(
			opts,
			newSetSockOptFunc("SO_SNDBUF", unix.SOL_SOCKET, unix.SO_SNDBUF, conf.SndBufSize),
		)
	}

	if conf.RcvBufSize > 0 {
		opts = append(
			opts,
			newSetSockOptFunc("SO_RCVBUF", unix.SOL_SOCKET, unix.SO_RCVBUF, conf.RcvBufSize),
		)
	}

	var opErr error
	err = c.Control(func(fd uintptr) {
		fdInt := int(fd)
		for _, opt := range opts {
			opErr = opt(fdInt)
			if opErr != nil {
				return
			}
		}
	})

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
