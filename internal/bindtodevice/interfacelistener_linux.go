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
//
// Data flow:
//
//  1. net.ListenConfig.Listen returns tcpListener.
//  2. tcpListener.Accept blocks until a new connection is accepted, then
//     returns the accepted conn.
//  3. processConn routes the accepted conn to a per-IP channel.
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

		// Route the accepted connection to the channel-listener registered for
		// its destination IP address.
		l.processConn(ctx, logger, conn)
	}
}

// processConn processes a single connection.  If the connection doesn't have a
// connected channel-listener, it is closed.
func (l *interfaceListener) processConn(ctx context.Context, logger *slog.Logger, conn net.Conn) {
	// Extract the local (destination) IP to look up the correct channel.
	laddr := netutil.NetAddrToAddrPort(conn.LocalAddr())
	raddr := conn.RemoteAddr()
	if lsnr := l.conns.listener(laddr.Addr()); lsnr != nil {
		// Forward the connection into the per-IP listener.
		if !lsnr.send(ctx, conn) {
			optslog.Debug2(ctx, logger, "channel is closed", "raddr", raddr, "laddr", laddr)
		}

		return
	}

	// No channel-listener is registered for this destination IP; drop the
	// connection and record the metric.
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
//
// Data flow:
//
//  1. net.ListenConfig.ListenPacket returns packet conn.
//  2. writeUDPResponses goroutine drains writeRequests (outbound path).
//  3. readUDP loop (inbound path).
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

	// Start the write goroutine so that inbound and outbound paths run
	// concurrently on the same UDP socket.
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

		// Each call blocks until one datagram is available.
		err = l.readUDP(ctx, logger, udpConn)
		if err != nil {
			errcoll.Collect(ctx, l.errColl, logger, "reading session", err)
		}
	}
}

// readUDP reads a UDP session from c and sends it to the appropriate channel.
// All arguments must not be nil.
//
// TODO(a.garipov):  Review error handling in order to simplify body bytes
// buffer management.
func (l *interfaceListener) readUDP(
	ctx context.Context,
	logger *slog.Logger,
	c *net.UDPConn,
) (err error) {
	// Acquire pooled buffers for this read operation.
	bodyPtr := l.bodyPool.Get()
	body := *bodyPtr

	// Extend body to the capacity in case it had already been used and sliced
	// by [readPacketSession].
	body = body[:cap(body)]

	oobPtr := l.oobPool.Get()
	oob := *oobPtr

	defer func() {
		// OOB buffer is only needed during readPacketSession; return it now.
		l.oobPool.Put(oobPtr)

		// Only return the body to the pool in case of error here.  The actual
		// return is done in writeUDP.
		if err != nil {
			l.bodyPool.Put(bodyPtr)
		}
	}()

	// Read session that captures remote addr, local addr, payload, and the OOB
	// bytes.
	sess, err := readPacketSession(c, body, oob)
	if err != nil {
		return fmt.Errorf("reading session: %w", err)
	}

	// Use the destination IP from the session to find the matching connection.
	laddr := sess.laddr.AddrPort().Addr()
	chanPacketConn := l.conns.packetConn(laddr)
	if chanPacketConn == nil {
		// No channel is registered for this destination IP; discard the
		// datagram and return the body buffer to the pool.
		l.metrics.IncrementUnknownUDPRequests(ctx)

		optslog.Debug2(ctx, logger, "no packet channel", "raddr", sess.raddr, "laddr", laddr)

		l.bodyPool.Put(bodyPtr)

		return nil
	}

	// Deliver the session to the per-IP channel.  On success, body ownership
	// moves to the session and will be released in writeUDP after the response
	// is sent.  On failure the body is returned to the pool here.
	if !chanPacketConn.send(ctx, sess) {
		optslog.Debug1(ctx, logger, "channel is closed", "laddr", laddr)

		l.bodyPool.Put(bodyPtr)
	}

	return nil
}

// writeUDPResponses runs the UDP write loop.  It is intended to be used as a
// goroutine.  All arguments must not be nil.
//
// Data flow:
//
//  1. writeRequests chan.  The channel is populated by
//     chanPacketConn.writeToSession.
//  2. writeUDP sets deadline, writes datagram, and signals completion.
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
			// Serialize all writes through this single goroutine so that the
			// deadline is set and reset atomically around each WriteMsgUDP call.
			l.writeUDP(ctx, logger, c, req)
		}
	}
}

// writeUDP handles a single write operation and writes a response to
// req.respCh.  All arguments must not be nil.
func (l *interfaceListener) writeUDP(
	ctx context.Context,
	logger *slog.Logger,
	c *net.UDPConn,
	req *packetConnWriteReq,
) {
	resp := &packetConnWriteResp{}
	resp.err = c.SetWriteDeadline(req.deadline)
	if resp.err != nil {
		// Return the response early.
		req.respCh <- resp

		// Release the body buffer that was held since readUDP.
		if s := req.session; s != nil {
			l.bodyPool.Put(&s.readBody)
		}

		return
	}

	l.writeToUDPConn(ctx, logger, c, req, resp)

	resetDeadlineErr := c.SetWriteDeadline(time.Time{})
	resp.err = errors.WithDeferred(resp.err, resetDeadlineErr)

	// Unblock the per-IP chanPacketConn waiting for the write result.
	req.respCh <- resp
}

// writeToUDPConn writes to c, depending on what kind of session req contains,
// and sets resp.written and resp.err accordingly.  All arguments must not be
// nil.
func (l *interfaceListener) writeToUDPConn(
	ctx context.Context,
	logger *slog.Logger,
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
		optslog.Debug1(ctx, logger, "no session", "raddr", req.raddr)

		// This must not happen since the session is created in readUDP and
		// passed in [netext.SessionPacketConn] by [netext.PacketSession], but
		// just in case, handle it gracefully.
		resp.written, resp.err = c.WriteTo(req.body, req.raddr)

		return
	}

	resp.written, _, resp.err = c.WriteMsgUDP(req.body, s.respOOB, s.raddr)

	// Release the inbound body buffer now that the response has been sent.
	l.bodyPool.Put(&s.readBody)
}
