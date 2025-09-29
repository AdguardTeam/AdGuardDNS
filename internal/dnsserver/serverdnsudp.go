package dnsserver

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

// serveUDP runs the UDP serving loop.  It is intended to be used as a
// goroutine.  conn must not be nil.
func (s *ServerDNS) serveUDP(ctx context.Context, conn net.PacketConn) {
	// Do not recover from panics here since if this goroutine panics, the
	// application won't be able to continue listening to UDP.
	defer s.handlePanicAndExit(ctx)

	s.baseLogger.InfoContext(ctx, "starting listening udp")
	defer func() { closeWithLog(ctx, s.baseLogger, "closing udp conn", conn) }()

	for s.isStarted() {
		err := s.acceptUDPMsg(ctx, conn)
		if err == nil {
			continue
		}

		// TODO(ameshkov):  Consider the situation where the server is shut down
		// and restarted between the two calls to isStarted.
		if !s.isStarted() {
			s.baseLogger.DebugContext(
				ctx,
				"listening udp failed: server not started",
				slogutil.KeyError, err,
			)
		} else {
			s.baseLogger.ErrorContext(ctx, "listening udp failed", slogutil.KeyError, err)
		}

		return
	}
}

// acceptUDPMsg reads and starts processing a single UDP message.
func (s *ServerDNS) acceptUDPMsg(ctx context.Context, conn net.PacketConn) (err error) {
	bufPtr := s.udpPool.Get()
	n, sess, err := s.readUDPMsg(ctx, conn, *bufPtr)
	if err != nil {
		s.udpPool.Put(bufPtr)

		if isNonCriticalNetError(err) || errors.Is(err, dns.ErrShortRead) {
			// Non-critical errors, do not register in the metrics or log
			// anywhere.
			return nil
		}

		return err
	}

	// Save the start time here, but create the context inside the goroutine,
	// since s.requestContext can be slow.
	//
	// TODO(a.garipov):  The slowness is likely due to constant reallocation of
	// timers in [context.WithTimeout].  Consider creating an optimized reusable
	// version.
	startTime := time.Now()

	return s.taskPool.submitWG(s.activeTaskWG, func() {
		reqCtx, reqCancel := s.requestContext(context.Background())
		defer reqCancel()

		reqCtx = ContextWithRequestInfo(reqCtx, &RequestInfo{
			StartTime: startTime,
		})

		s.serveUDPPacket(reqCtx, (*bufPtr)[:n], conn, sess)
		s.udpPool.Put(bufPtr)
	})
}

// serveUDPPacket serves a new UDP request.  It is intended to be used as a
// goroutine.  buf, conn, and sess must not be nil.
func (s *ServerDNS) serveUDPPacket(
	ctx context.Context,
	buf []byte,
	conn net.PacketConn,
	sess netext.PacketSession,
) {
	defer s.handlePanicAndRecover(ctx)

	s.serveDNS(ctx, buf, &udpResponseWriter{
		respPool:     s.respPool,
		udpSession:   sess,
		conn:         conn,
		writeTimeout: s.writeTimeout,
		maxRespSize:  s.maxUDPRespSize,
	})
}

// readUDPMsg reads the next incoming DNS message.
func (s *ServerDNS) readUDPMsg(
	ctx context.Context,
	conn net.PacketConn,
	buf []byte,
) (n int, sess netext.PacketSession, err error) {
	err = conn.SetReadDeadline(time.Now().Add(s.readTimeout))
	if err != nil {
		return 0, nil, err
	}

	n, sess, err = netext.ReadFromSession(conn, buf)
	if err != nil {
		return 0, nil, err
	}

	if n < DNSHeaderSize {
		s.metrics.OnInvalidMsg(ctx)

		return 0, nil, dns.ErrShortRead
	}

	return n, sess, nil
}

// udpResponseWriter is a ResponseWriter implementation for DNS-over-UDP.
type udpResponseWriter struct {
	respPool     *syncutil.Pool[[]byte]
	udpSession   netext.PacketSession
	conn         net.PacketConn
	writeTimeout time.Duration
	maxRespSize  uint16
}

// type check
var _ ResponseWriter = (*udpResponseWriter)(nil)

// LocalAddr implements the ResponseWriter interface for *udpResponseWriter.
func (r *udpResponseWriter) LocalAddr() (addr net.Addr) {
	// Don't use r.conn.LocalAddr(), since udpSession may actually contain the
	// decoded OOB data, including the real local (dst) address.
	return r.udpSession.LocalAddr()
}

// RemoteAddr implements the ResponseWriter interface for *udpResponseWriter.
func (r *udpResponseWriter) RemoteAddr() (addr net.Addr) {
	// Don't use r.conn.RemoteAddr(), since udpSession may actually contain the
	// decoded OOB data, including the real remote (src) address.
	return r.udpSession.RemoteAddr()
}

// WriteMsg implements the ResponseWriter interface for *udpResponseWriter.
func (r *udpResponseWriter) WriteMsg(ctx context.Context, req, resp *dns.Msg) (err error) {
	normalize(NetworkUDP, ProtoDNS, req, resp, r.maxRespSize)

	bufPtr := r.respPool.Get()
	defer func() {
		if err != nil {
			r.respPool.Put(bufPtr)
		}
	}()

	b, err := resp.PackBuffer(*bufPtr)
	if err != nil {
		return fmt.Errorf("udp: packing response: %w", err)
	}

	*bufPtr = b

	withWriteDeadline(ctx, r.writeTimeout, r.conn, func() {
		_, err = netext.WriteToSession(r.conn, b, r.udpSession)
	})

	if err != nil {
		return &WriteError{
			Err:      err,
			Protocol: "udp",
		}
	}

	return nil
}
