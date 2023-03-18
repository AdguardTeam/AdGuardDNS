//go:build linux

package bindtodevice

import (
	"fmt"
	"net"
	"syscall"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"golang.org/x/sys/unix"
)

// newListenConfig returns a [net.ListenConfig] that can bind to a network
// interface (device) by its name.
func newListenConfig(devName string) (lc *net.ListenConfig) {
	c := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) (err error) {
			return listenControl(devName, network, address, c)
		},
	}

	return c
}

// listenControl is used as a [net.ListenConfig.Control] function to set
// additional socket options, including SO_BINDTODEVICE.
func listenControl(devName, network, _ string, c syscall.RawConn) (err error) {
	var ctrlFunc func(fd uintptr, devName string) (err error)

	switch network {
	case "tcp", "tcp4", "tcp6":
		ctrlFunc = setTCPSockOpt
	case "udp", "udp4", "udp6":
		ctrlFunc = setUDPSockOpt
	default:
		return fmt.Errorf("bad network %q", network)
	}

	var opErr error
	err = c.Control(func(fd uintptr) {
		opErr = ctrlFunc(fd, devName)
	})

	return errors.WithDeferred(opErr, err)
}

// setTCPSockOpt sets the SO_BINDTODEVICE and other socket options for a TCP
// connection.
func setTCPSockOpt(fd uintptr, devName string) (err error) {
	defer func() { err = errors.Annotate(err, "setting tcp opts: %w") }()

	fdInt := int(fd)
	err = unix.SetsockoptString(fdInt, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, devName)
	if err != nil {
		return fmt.Errorf("setting SO_BINDTODEVICE: %w", err)
	}

	err = unix.SetsockoptInt(fdInt, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	if err != nil {
		return fmt.Errorf("setting SO_REUSEPORT: %w", err)
	}

	return nil
}

// setUDPSockOpt sets the SO_BINDTODEVICE and other socket options for a UDP
// connection.
func setUDPSockOpt(fd uintptr, devName string) (err error) {
	defer func() { err = errors.Annotate(err, "setting udp opts: %w") }()

	fdInt := int(fd)
	err = unix.SetsockoptString(fdInt, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, devName)
	if err != nil {
		return fmt.Errorf("setting SO_BINDTODEVICE: %w", err)
	}

	intOpts := []struct {
		name  string
		level int
		opt   int
	}{{
		name:  "SO_REUSEPORT",
		level: unix.SOL_SOCKET,
		opt:   unix.SO_REUSEPORT,
	}, {
		name:  "IP_RECVORIGDSTADDR",
		level: unix.IPPROTO_IP,
		opt:   unix.IP_RECVORIGDSTADDR,
	}, {
		name:  "IP_FREEBIND",
		level: unix.IPPROTO_IP,
		opt:   unix.IP_FREEBIND,
	}, {
		name:  "IPV6_RECVORIGDSTADDR",
		level: unix.IPPROTO_IPV6,
		opt:   unix.IPV6_RECVORIGDSTADDR,
	}, {
		name:  "IPV6_FREEBIND",
		level: unix.IPPROTO_IPV6,
		opt:   unix.IPV6_FREEBIND,
	}}

	for _, o := range intOpts {
		err = unix.SetsockoptInt(fdInt, o.level, o.opt, 1)
		if err != nil {
			return fmt.Errorf("setting %s: %w", o.name, err)
		}
	}

	return nil
}

// readPacketSession is a helper that reads a packet-session data from a UDP
// connection.
func readPacketSession(c *net.UDPConn, bodySize int) (sess *packetSession, err error) {
	// TODO(a.garipov): Consider adding pooling.
	b := make([]byte, bodySize)
	oob := make([]byte, netext.IPDstOOBSize)

	n, oobn, _, raddr, err := c.ReadMsgUDP(b, oob)
	if err != nil {
		return nil, fmt.Errorf("reading: %w", err)
	}

	var ctrlMsgs []unix.SocketControlMessage
	ctrlMsgs, err = unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, fmt.Errorf("parsing ctrl messages: %w", err)
	}

	if l := len(ctrlMsgs); l != 1 {
		return nil, fmt.Errorf("expected 1 ctrl message, got %d", l)
	}

	ctrlMsg := ctrlMsgs[0]
	origDstSockAddr, err := unix.ParseOrigDstAddr(&ctrlMsg)
	if err != nil {
		return nil, fmt.Errorf("parsing orig dst: %w", err)
	}

	origDstAddr, respOOB, err := sockAddrData(origDstSockAddr)
	if err != nil {
		return nil, err
	}

	sess = &packetSession{
		laddr:    origDstAddr,
		raddr:    raddr,
		readBody: b[:n],
		respOOB:  respOOB,
	}

	return sess, nil
}

// sockAddrData converts the provided socket address into a UDP address as well
// as encodes the response packet information.
func sockAddrData(sockAddr unix.Sockaddr) (origDstAddr *net.UDPAddr, respOOB []byte, err error) {
	switch sockAddr := sockAddr.(type) {
	case *unix.SockaddrInet4:
		origDstAddr = &net.UDPAddr{
			IP:   sockAddr.Addr[:],
			Port: sockAddr.Port,
		}

		pktInfo := &unix.Inet4Pktinfo{
			Addr: sockAddr.Addr,
		}

		respOOB = unix.PktInfo4(pktInfo)
	case *unix.SockaddrInet6:
		origDstAddr = &net.UDPAddr{
			IP:   sockAddr.Addr[:],
			Port: sockAddr.Port,
		}

		pktInfo := &unix.Inet6Pktinfo{
			Addr:    sockAddr.Addr,
			Ifindex: sockAddr.ZoneId,
		}

		respOOB = unix.PktInfo6(pktInfo)
	default:
		return nil, nil, fmt.Errorf("bad orig dst sockaddr type %T", sockAddr)
	}

	return origDstAddr, respOOB, nil
}
