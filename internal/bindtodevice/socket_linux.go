//go:build linux

package bindtodevice

import (
	"fmt"
	"net"
	"syscall"

	"github.com/AdguardTeam/golibs/errors"
	"golang.org/x/sys/unix"
)

// setSockOptFunc is a function that sets a socket option on fd.
type setSockOptFunc func(fd int) (err error)

// newIntSetSockOptFunc returns an integer socket-option function with the given
// parameters.
func newIntSetSockOptFunc(name string, lvl, opt, val int) (o setSockOptFunc) {
	return func(fd int) (err error) {
		opErr := unix.SetsockoptInt(fd, lvl, opt, val)

		return errors.Annotate(opErr, "setting %s: %w", name)
	}
}

// newStringSetSockOptFunc returns a string socket-option function with the
// given parameters.
func newStringSetSockOptFunc(name string, lvl, opt int, val string) (o setSockOptFunc) {
	return func(fd int) (err error) {
		opErr := unix.SetsockoptString(fd, lvl, opt, val)

		return errors.Annotate(opErr, "setting %s: %w", name)
	}
}

// newListenConfig returns a [net.ListenConfig] that can bind to a network
// interface (device) by its name.  ctrlConf must not be nil.
func newListenConfig(devName string, ctrlConf *ControlConfig) (lc *net.ListenConfig) {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) (err error) {
			return listenControlWithSO(ctrlConf, devName, network, address, c)
		},
	}
}

// listenControlWithSO is used as a [net.ListenConfig.Control] function to set
// additional socket options.
func listenControlWithSO(
	ctrlConf *ControlConfig,
	devName string,
	network string,
	_ string,
	c syscall.RawConn,
) (err error) {
	opts := []setSockOptFunc{
		newStringSetSockOptFunc("SO_BINDTODEVICE", unix.SOL_SOCKET, unix.SO_BINDTODEVICE, devName),
		// Use SO_REUSEADDR as well, which is not technically necessary, to
		// help with the situation of sockets hanging in CLOSE_WAIT for too
		// long.
		newIntSetSockOptFunc("SO_REUSEADDR", unix.SOL_SOCKET, unix.SO_REUSEADDR, 1),
		newIntSetSockOptFunc("SO_REUSEPORT", unix.SOL_SOCKET, unix.SO_REUSEPORT, 1),
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		// Socket options for TCP connection already set.  Go on.
	case "udp", "udp4", "udp6":
		opts = append(
			opts,
			newIntSetSockOptFunc("IP_RECVORIGDSTADDR", unix.IPPROTO_IP, unix.IP_RECVORIGDSTADDR, 1),
			newIntSetSockOptFunc("IP_FREEBIND", unix.IPPROTO_IP, unix.IP_FREEBIND, 1),
			newIntSetSockOptFunc("IPV6_RECVORIGDSTADDR", unix.IPPROTO_IPV6, unix.IPV6_RECVORIGDSTADDR, 1),
			newIntSetSockOptFunc("IPV6_FREEBIND", unix.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1),
		)
	default:
		return fmt.Errorf("bad network %q", network)
	}

	if ctrlConf.SndBufSize > 0 {
		opts = append(
			opts,
			newIntSetSockOptFunc("SO_SNDBUF", unix.SOL_SOCKET, unix.SO_SNDBUF, ctrlConf.SndBufSize),
		)
	}

	if ctrlConf.RcvBufSize > 0 {
		opts = append(
			opts,
			newIntSetSockOptFunc("SO_RCVBUF", unix.SOL_SOCKET, unix.SO_RCVBUF, ctrlConf.RcvBufSize),
		)
	}

	var opErr error
	err = c.Control(func(fd uintptr) {
		d := int(fd)
		for _, opt := range opts {
			opErr = opt(d)
			if opErr != nil {
				return
			}
		}
	})

	return errors.WithDeferred(opErr, err)
}

// msgUDPReader is an interface for types of connections that can read UDP
// messages.  See [*net.UDPConn].
type msgUDPReader interface {
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
}

// readPacketSession is a helper that reads a packet-session data from a UDP
// connection.
func readPacketSession(c msgUDPReader, body, oob []byte) (sess *packetSession, err error) {
	n, oobn, _, raddr, err := c.ReadMsgUDP(body, oob)
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
		readBody: body[:n],
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

		// Set both addresses to make sure that users receive the correct source
		// IP address even when virtual interfaces are involved.
		pktInfo := &unix.Inet4Pktinfo{
			Addr:     sockAddr.Addr,
			Spec_dst: sockAddr.Addr,
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
