//go:build linux

package bindtodevice

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// interfaceListener contains information about a single interface listener.
type interfaceListener struct {
	channels      *chanIndex
	writeRequests chan *packetConnWriteReq
	done          chan unit
	listenConf    *net.ListenConfig
	errColl       agd.ErrorCollector
	ifaceName     string
	port          uint16
}

// listenTCP runs the TCP listening loop.  It is intended to be used as a
// goroutine.  errCh receives nil if the listening has started successfully or
// the listening error if not.
func (l *interfaceListener) listenTCP(errCh chan<- error) {
	defer log.OnPanic("interfaceListener.listenTCP")

	ctx := context.Background()
	addrStr := netutil.JoinHostPort("0.0.0.0", int(l.port))
	tcpListener, err := l.listenConf.Listen(ctx, "tcp", addrStr)

	errCh <- err
	if err != nil {
		return
	}

	logPrefix := fmt.Sprintf("bindtodevice: listener %s:%d: tcp", l.ifaceName, l.port)

	log.Info("%s: starting", logPrefix)

	for {
		select {
		case <-l.done:
			log.Info("%s: done", logPrefix)

			return
		default:
			// Go on.
		}

		var conn net.Conn
		conn, err = tcpListener.Accept()
		if err != nil {
			agd.Collectf(ctx, l.errColl, "%s: accepting: %w", logPrefix, err)

			continue
		}

		laddr := netutil.NetAddrToAddrPort(conn.LocalAddr())
		ch := l.channels.listenerChannel(laddr.Addr())
		if ch == nil {
			log.Info("%s: no channel for laddr %s", logPrefix, laddr)

			continue
		}

		ch <- conn
	}
}

// listenUDP runs the UDP listening loop.  It is intended to be used as a
// goroutine.  errCh receives nil if the listening has started successfully or
// the listening error if not.
func (l *interfaceListener) listenUDP(errCh chan<- error) {
	defer log.OnPanic("interfaceListener.listenUDP")

	ctx := context.Background()
	addrStr := netutil.JoinHostPort("0.0.0.0", int(l.port))
	packetConn, err := l.listenConf.ListenPacket(ctx, "udp", addrStr)
	if err != nil {
		errCh <- err

		return
	}

	udpConn := packetConn.(*net.UDPConn)

	errCh <- nil

	go l.writeUDP(udpConn)

	logPrefix := fmt.Sprintf("bindtodevice: listener %s:%d: udp", l.ifaceName, l.port)

	log.Info("%s: starting", logPrefix)

	for {
		select {
		case <-l.done:
			log.Info("%s: done", logPrefix)

			return
		default:
			// Go on.
		}

		// TODO(a.garipov): Consider customization of body sizes.
		var sess *packetSession
		sess, err = readPacketSession(udpConn, dns.DefaultMsgSize)
		if err != nil {
			agd.Collectf(ctx, l.errColl, "%s: reading session: %w", logPrefix, err)

			continue
		}

		laddr := sess.laddr.AddrPort().Addr()
		ch := l.channels.packetConnChannel(laddr)
		if ch == nil {
			log.Info("%s: no channel for laddr %s", logPrefix, laddr)

			continue
		}

		ch <- sess
	}
}

// writeUDP runs the UDP write loop.  It is intended to be used as a goroutine.
func (l *interfaceListener) writeUDP(c *net.UDPConn) {
	defer log.OnPanic("interfaceListener.writeUDP")

	logPrefix := fmt.Sprintf("bindtodevice: listener %s:%d: udp write", l.ifaceName, l.port)
	for {
		var req *packetConnWriteReq
		select {
		case <-l.done:
			log.Info("%s: done", logPrefix)

			return
		case req = <-l.writeRequests:
			// Go on.
		}

		resp := &packetConnWriteResp{}
		resp.err = c.SetWriteDeadline(req.deadline)
		if resp.err != nil {
			req.resp <- resp

			continue
		}

		if s := req.session; s == nil {
			resp.written, resp.err = c.WriteTo(req.body, req.raddr)
		} else {
			resp.written, _, resp.err = c.WriteMsgUDP(
				req.body,
				s.respOOB,
				req.session.raddr,
			)
		}

		resetDeadlineErr := c.SetWriteDeadline(time.Time{})

		resp.err = errors.WithDeferred(resp.err, resetDeadlineErr)

		req.resp <- resp
	}
}
