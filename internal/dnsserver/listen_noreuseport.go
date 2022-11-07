//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package dnsserver

import (
	"context"
	"fmt"
	"net"

	"github.com/AdguardTeam/golibs/errors"
)

// listenUDP listens to the specified address on UDP.
func listenUDP(_ context.Context, addr string, _ bool) (conn *net.UDPConn, err error) {
	defer func() { err = errors.Annotate(err, "opening packet listener: %w") }()

	c, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}

	conn, ok := c.(*net.UDPConn)
	if !ok {
		// TODO(ameshkov): should not happen, consider panic here.
		err = fmt.Errorf("expected conn of type %T, got %T", conn, c)

		return nil, err
	}

	return conn, nil
}

// listenTCP listens to the specified address on TCP.
func listenTCP(_ context.Context, addr string) (conn net.Listener, err error) {
	return net.Listen("tcp", addr)
}
