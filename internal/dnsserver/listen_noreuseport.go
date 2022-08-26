//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package dnsserver

import (
	"context"
	"net"
)

// listenUDP listens to the specified address on UDP.
func listenUDP(_ context.Context, addr string) (conn net.PacketConn, err error) {
	return net.ListenPacket("udp", addr)
}

// listenTCP listens to the specified address on TCP.
func listenTCP(_ context.Context, addr string) (conn net.Listener, err error) {
	return net.Listen("tcp", addr)
}
