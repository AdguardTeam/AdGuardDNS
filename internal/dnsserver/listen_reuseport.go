//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd

package dnsserver

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"github.com/AdguardTeam/golibs/errors"
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

// listenUDP listens to the specified address on UDP.  If oob flag is set to
// true this method also enables OOB for the listen socket that enables using of
// ReadMsgUDP/WriteMsgUDP.  Doing it this way is necessary to correctly discover
// the source address when it listens to 0.0.0.0.
func listenUDP(ctx context.Context, addr string, oob bool) (conn *net.UDPConn, err error) {
	defer func() { err = errors.Annotate(err, "opening packet listener: %w") }()

	var lc net.ListenConfig
	lc.Control = reuseportControl
	c, err := lc.ListenPacket(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}

	conn, ok := c.(*net.UDPConn)
	if !ok {
		// TODO(ameshkov): should not happen, consider panic here.
		err = fmt.Errorf("expected conn of type %T, got %T", conn, c)

		return nil, err
	}

	if oob {
		if err = setUDPSocketOptions(conn); err != nil {
			return nil, fmt.Errorf("failed to set socket options: %w", err)
		}
	}

	return conn, err
}

// listenTCP listens to the specified address on TCP.
func listenTCP(ctx context.Context, addr string) (l net.Listener, err error) {
	var lc net.ListenConfig
	lc.Control = reuseportControl
	return lc.Listen(ctx, "tcp", addr)
}
