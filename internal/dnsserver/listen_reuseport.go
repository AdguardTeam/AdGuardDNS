//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd

package dnsserver

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func reuseportControl(_, _ string, c syscall.RawConn) (err error) {
	var opErr error
	err = c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}

	return opErr
}

// listenUDP listens to the specified address on UDP.
func listenUDP(ctx context.Context, addr string) (conn net.PacketConn, err error) {
	var lc net.ListenConfig
	lc.Control = reuseportControl
	return lc.ListenPacket(ctx, "udp", addr)
}

// listenTCP listens to the specified address on TCP.
func listenTCP(ctx context.Context, addr string) (l net.Listener, err error) {
	var lc net.ListenConfig
	lc.Control = reuseportControl
	return lc.Listen(ctx, "tcp", addr)
}
