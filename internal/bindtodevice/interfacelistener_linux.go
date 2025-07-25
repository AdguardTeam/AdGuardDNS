//go:build linux

package bindtodevice

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/optslog"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
)

// interfaceListener contains information about a single interface listener.
type interfaceListener struct {
	logger        *slog.Logger
	conns         *connIndex
	listenConf    *net.ListenConfig
	bodyPool      *syncutil.Pool[[]byte]
	oobPool       *syncutil.Pool[[]byte]
	writeRequests chan *packetConnWriteReq
	done          chan unit
	errColl       errcoll.Interface
	metrics       Metrics
	ifaceName     string
	port          uint16
}

// listenTCP runs the TCP listening loop.  It is intended to be used as a
// goroutine.  errCh receives nil if the listening has started successfully or
// the listening error if not.
func (l *interfaceListener) listenTCP(ctx context.Context, errCh chan<- error) {
	logger := l.logger.With("network", "tcp")
	defer slogutil.RecoverAndLog(ctx, logger)

	addrStr := netutil.JoinHostPort("0.0.0.0", l.port)
	tcpListener, err := l.listenConf.Listen(ctx, "tcp", addrStr)

	errCh <- err
	if err != nil {
		return
	}

	logger.InfoContext(ctx, "starting")

	for {
		select {
		case <-l.done:
			logger.InfoContext(ctx, "done")

			return
		default:
			// Go on.
		}

		var conn net.Conn
		conn, err = tcpListener.Accept()
		if err != nil {
			errcoll.Collect(ctx, l.errColl, logger, "accepting", err)

			continue
		}

		l.processConn(ctx, logger, conn)
	}
}

// processConn processes a single connection.  If the connection doesn't have a
// connected channel-listener, it is closed.
func (l *interfaceListener) processConn(ctx context.Context, logger *slog.Logger, conn net.Conn) {
	laddr := netutil.NetAddrToAddrPort(conn.LocalAddr())
	raddr := conn.RemoteAddr()
	if lsnr := l.conns.listener(laddr.Addr()); lsnr != nil {
		if !lsnr.send(ctx, conn) {
			optslog.Debug2(ctx, logger, "channel is closed", "raddr", raddr, "laddr", laddr)
		}

		return
	}

	l.metrics.IncrementUnknownTCPRequests(ctx)

	optslog.Debug2(ctx, logger, "no stream channel", "raddr", raddr, "laddr", laddr)

	err := conn.Close()
	if err != nil {
		optslog.Debug2(ctx, logger, "closing", "raddr", raddr, slogutil.KeyError, err)
	}
}

// listenUDP runs the UDP listening loop.  It is intended to be used as a
// goroutine.  errCh receives nil if the listening has started successfully or
// the listening error if not.
func (l *interfaceListener) listenUDP(ctx context.Context, errCh chan<- error) {
	logger := l.logger.With("network", "udp")
	defer slogutil.RecoverAndLog(ctx, logger)

	addrStr := netutil.JoinHostPort("0.0.0.0", l.port)
	packetConn, err := l.listenConf.ListenPacket(ctx, "udp", addrStr)
	if err != nil {
		errCh <- err

		return
	}

	udpConn := packetConn.(*net.UDPConn)

	errCh <- nil

	go l.writeUDPResponses(ctx, logger, udpConn)

	logger.InfoContext(ctx, "starting")

	for {
		select {
		case <-l.done:
			logger.InfoContext(ctx, "done")

			return
		default:
			// Go on.
		}

		err = l.readUDP(ctx, logger, udpConn)
		if err != nil {
			errcoll.Collect(ctx, l.errColl, logger, "reading session", err)
		}
	}
}

// readUDP reads a UDP session from c and sends it to the appropriate channel.
func (l *interfaceListener) readUDP(
	ctx context.Context,
	logger *slog.Logger,
	c *net.UDPConn,
) (err error) {
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
		l.metrics.IncrementUnknownUDPRequests(ctx)

		optslog.Debug2(ctx, logger, "no packet channel", "raddr", sess.raddr, "laddr", laddr)

		return nil
	}

	if !chanPacketConn.send(ctx, sess) {
		optslog.Debug1(ctx, logger, "channel is closed", "laddr", laddr)
	}

	return nil
}

// writeUDPResponses runs the UDP write loop.  It is intended to be used as a
// goroutine.
func (l *interfaceListener) writeUDPResponses(
	ctx context.Context,
	logger *slog.Logger,
	c *net.UDPConn,
) {
	defer slogutil.RecoverAndLog(ctx, logger)

	for {
		select {
		case <-l.done:
			logger.DebugContext(ctx, "udp write done")

			return
		case req := <-l.writeRequests:
			l.writeUDP(ctx, c, req)
		}
	}
}

// writeUDP handles a single write operation and writes a response to
// req.respCh.
func (l *interfaceListener) writeUDP(ctx context.Context, c *net.UDPConn, req *packetConnWriteReq) {
	resp := &packetConnWriteResp{}
	resp.err = c.SetWriteDeadline(req.deadline)
	if resp.err != nil {
		req.respCh <- resp

		return
	}

	l.writeToUDPConn(ctx, c, req, resp)

	resetDeadlineErr := c.SetWriteDeadline(time.Time{})
	resp.err = errors.WithDeferred(resp.err, resetDeadlineErr)

	req.respCh <- resp
}

// writeToUDPConn writes to c, depending on what kind of session req contains,
// and sets resp.written and resp.err accordingly.
func (l *interfaceListener) writeToUDPConn(
	ctx context.Context,
	c *net.UDPConn,
	req *packetConnWriteReq,
	resp *packetConnWriteResp,
) {
	start := time.Now()
	defer func() {
		l.metrics.ObserveUDPWriteDuration(ctx, l.ifaceName, time.Since(start))
	}()

	s := req.session
	if s == nil {
		resp.written, resp.err = c.WriteTo(req.body, req.raddr)

		return
	}

	resp.written, _, resp.err = c.WriteMsgUDP(req.body, s.respOOB, req.session.raddr)

	l.bodyPool.Put(&s.readBody)
}
