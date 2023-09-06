//go:build linux

package bindtodevice

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdsync"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
)

// interfaceListener contains information about a single interface listener.
type interfaceListener struct {
	conns         *connIndex
	listenConf    *net.ListenConfig
	bodyPool      *agdsync.TypedPool[[]byte]
	oobPool       *agdsync.TypedPool[[]byte]
	writeRequests chan *packetConnWriteReq
	done          chan unit
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

		l.processConn(conn, logPrefix)
	}
}

// processConn processes a single connection.  If the connection doesn't have a
// connected channel-listener, it is closed.
func (l *interfaceListener) processConn(conn net.Conn, logPrefix string) {
	laddr := netutil.NetAddrToAddrPort(conn.LocalAddr())
	raddr := conn.RemoteAddr()
	if lsnr := l.conns.listener(laddr.Addr()); lsnr != nil {
		if !lsnr.send(conn) {
			log.Info("%s: from raddr %s: channel for laddr %s is closed", logPrefix, raddr, laddr)
		}

		return
	}

	metrics.BindToDeviceUnknownTCPRequestsTotal.Inc()

	optlog.Debug3("%s: from raddr %s: no stream channel for laddr %s", logPrefix, raddr, laddr)

	err := conn.Close()
	if err != nil {
		log.Debug("%s: from raddr %s: closing: %s", logPrefix, raddr, err)
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

		err = l.readUDP(udpConn, logPrefix)
		if err != nil {
			agd.Collectf(ctx, l.errColl, "%s: reading session: %w", logPrefix, err)
		}
	}
}

// readUDP reads a UDP session from c and sends it to the appropriate channel.
func (l *interfaceListener) readUDP(c *net.UDPConn, logPrefix string) (err error) {
	bodyPtr := l.bodyPool.Get()
	body := *bodyPtr

	// Extend body to the capacity in case it had already been used and sliced
	// by [readPacketSession].
	body = body[:cap(body)]

	oobPtr := l.oobPool.Get()
	oob := *oobPtr

	defer func() {
		l.oobPool.Put(oobPtr)

		// Only return the body to the pool in case of error here.  The actual
		// return is done in writeUDP.
		if err != nil {
			l.bodyPool.Put(bodyPtr)
		}
	}()

	sess, err := readPacketSession(c, body, oob)
	if err != nil {
		return fmt.Errorf("reading session: %w", err)
	}

	laddr := sess.laddr.AddrPort().Addr()
	chanPacketConn := l.conns.packetConn(laddr)
	if chanPacketConn == nil {
		metrics.BindToDeviceUnknownUDPRequestsTotal.Inc()

		optlog.Debug3(
			"%s: from raddr %s: no packet channel for laddr %s",
			logPrefix,
			sess.raddr,
			laddr,
		)

		return nil
	}

	if !chanPacketConn.send(sess) {
		log.Info("%s: channel for laddr %s is closed", logPrefix, laddr)
	}

	return nil
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

			l.bodyPool.Put(&s.readBody)
		}

		resetDeadlineErr := c.SetWriteDeadline(time.Time{})

		resp.err = errors.WithDeferred(resp.err, resetDeadlineErr)

		req.resp <- resp
	}
}
