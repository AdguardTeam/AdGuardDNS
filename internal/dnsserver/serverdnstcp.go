package dnsserver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

// tcpLengthPrefixSize is the size of the length prefix in responses via TCP.
const tcpLengthPrefixSize = 2

// serveTCP runs the TCP serving loop.  It is intended to be used as a
// goroutine.  l must not be nil.
func (s *ServerDNS) serveTCP(ctx context.Context, l net.Listener, proto string) {
	// Do not recover from panics here since if this goroutine panics, the
	// application won't be able to continue listening to TCP.
	defer s.handlePanicAndExit(ctx)

	s.baseLogger.InfoContext(ctx, "starting listening tcp")
	defer func() { closeWithLog(ctx, s.baseLogger, "closing tcp listener", l) }()

	for s.isStarted() {
		err := s.acceptTCPConn(ctx, l)
		if err == nil {
			continue
		}

		// TODO(ameshkov):  Consider the situation where the server is shut down
		// and restarted between the two calls to isStarted.
		if !s.isStarted() {
			s.baseLogger.DebugContext(
				ctx,
				"listening tcp failed: server not started",
				"proto", proto,
				slogutil.KeyError, err,
			)
		} else {
			s.baseLogger.ErrorContext(
				ctx,
				"listening tcp failed",
				"proto", proto,
				slogutil.KeyError, err,
			)
		}

		return
	}
}

// acceptTCPConn reads and starts processing a single TCP connection.
//
// NOTE:  Any error returned from this method stops handling on l.
func (s *ServerDNS) acceptTCPConn(ctx context.Context, l net.Listener) (err error) {
	conn, err := l.Accept()
	if err != nil {
		if isNonCriticalNetError(err) {
			// Non-critical errors, do not register in the metrics or log
			// anywhere.
			return nil
		}

		return err
	}
	defer func() { closeOnError(ctx, s.baseLogger, conn, recover(), err) }()

	func() {
		s.tcpConnsMu.Lock()
		defer s.tcpConnsMu.Unlock()

		// Track the connection to allow unblocking reads on shutdown.
		s.tcpConns.Add(conn)
	}()

	// The error returned by submitWG most likely means that the taskPool is
	// closed, so return it to stop handling.
	return s.taskPool.submitWG(s.activeTaskWG, func() {
		defer s.handlePanicAndRecover(ctx)

		s.serveTCPConn(ctx, conn)
	})
}

// handshaker is the interface for connections that can perform handshake.
type handshaker interface {
	net.Conn

	HandshakeContext(ctx context.Context) (err error)
}

// handshake performs a TLS handshake if the connection is a [handshaker].  This
// is useful to prevent writes during reads and reads during writes for TLS
// connections.
func handshake(conn net.Conn, timeout time.Duration) (err error) {
	shaker, ok := conn.(handshaker)
	if !ok {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return shaker.HandshakeContext(ctx)
}

// serveTCPConn serves a single TCP connection.  conn must not be nil.
func (s *ServerDNS) serveTCPConn(ctx context.Context, conn net.Conn) {
	connWG := &sync.WaitGroup{}
	defer func() {
		connWG.Wait()

		closeWithLog(ctx, s.baseLogger, "closing tcp conn", conn)

		s.tcpConnsMu.Lock()
		defer s.tcpConnsMu.Unlock()

		s.tcpConns.Delete(conn)
	}()

	var msgSema syncutil.Semaphore = syncutil.EmptySemaphore{}
	if s.maxPipelineEnabled {
		msgSema = syncutil.NewChanSemaphore(s.maxPipelineCount)
	}

	// writeMu serializes write deadline setting and writing to conn.
	writeMu := &sync.Mutex{}

	timeout := s.readTimeout
	idleTimeout := s.tcpIdleTimeout

	err := handshake(conn, timeout)
	if err != nil {
		s.logReadErr(ctx, "handshaking", err)

		return
	}

	for s.isStarted() {
		err = s.acceptTCPMsg(ctx, conn, connWG, writeMu, timeout, msgSema)
		if err != nil {
			s.logReadErr(ctx, "reading from conn", err)

			return
		}

		// Use idle timeout for further queries.
		timeout = idleTimeout
	}
}

// logReadErr logs err on debug level unless it's trivial ([io.EOF] or
// [net.ErrClosed]).
func (s *ServerDNS) logReadErr(ctx context.Context, msg string, err error) {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return
	}

	s.baseLogger.DebugContext(ctx, msg, slogutil.KeyError, err)
}

// tlsConnectionStater is a common interface for connections that can return
// a TLS connection state.
type tlsConnectionStater interface {
	ConnectionState() tls.ConnectionState
}

// acceptTCPMsg reads and starts processing a single TCP message.  If conn is a
// TLS connection, the handshake must have already been performed.  All
// arguments must not be empty.
//
// NOTE:  Any error returned from this method stops handling on conn.
func (s *ServerDNS) acceptTCPMsg(
	ctx context.Context,
	conn net.Conn,
	connWG *sync.WaitGroup,
	writeMu *sync.Mutex,
	timeout time.Duration,
	msgSema syncutil.Semaphore,
) (err error) {
	req, err := s.readTCPMsg(ctx, conn, timeout)
	if err != nil {
		// Likely an idle timeout or a bad message.
		//
		// TODO(a.garipov):  Consider not interrupting the conn handling on bad
		// messages.
		return fmt.Errorf("reading tcp message: %w", err)
	}

	reqCtx, reqCancel := s.newContextForTCPReq(ctx, conn)
	defer func() { callOnError(reqCancel, recover(), err) }()

	rw := s.newTCPRW(writeMu, conn)
	err = s.acquireSema(reqCtx, s.activeRequestsSema, req, rw, errMsgActiveReqSema)
	if err != nil {
		// Do not interrupt handling on semaphore timeouts.
		return nil
	}
	defer func() { callOnError(s.activeRequestsSema.Release, recover(), err) }()

	err = s.acquireSema(reqCtx, msgSema, req, rw, "acquiring pipeline semaphore")
	if err != nil {
		// Do not interrupt handling on semaphore timeouts.
		return nil
	}
	defer func() { callOnError(msgSema.Release, recover(), err) }()

	// The error returned by submitWG most likely means that the taskPool is
	// closed, so return it to stop handling.
	return s.taskPool.submitWG(connWG, func() {
		defer s.handlePanicAndRecover(reqCtx)
		defer reqCancel()
		defer msgSema.Release()
		defer s.activeRequestsSema.Release()

		written := s.serveDNSMsg(reqCtx, req, rw)
		if !written {
			// Nothing has been written, so close the connection in order to
			// avoid hanging connections.  That can happen when the handler
			// rate-limited a connection or if garbage data has been received.
			slogutil.CloseAndLog(ctx, s.baseLogger, conn, slog.LevelDebug)
		}
	})
}

// newTCPRW returns a new TCP response writer for a request.  All arguments must
// not be nil.
func (s *ServerDNS) newTCPRW(writeMu *sync.Mutex, conn net.Conn) (rw *tcpResponseWriter) {
	return &tcpResponseWriter{
		respPool:     s.respPool,
		writeMu:      writeMu,
		conn:         conn,
		writeTimeout: s.writeTimeout,
		idleTimeout:  s.tcpIdleTimeout,
	}
}

// newContextForTCPReq returns a new context for a TCP request.  All arguments
// must not be nil.
func (s *ServerDNS) newContextForTCPReq(
	parent context.Context,
	conn net.Conn,
) (ctx context.Context, cancel context.CancelFunc) {
	ctx, cancel = s.reqCtx.New(context.WithoutCancel(parent))

	ri := &RequestInfo{
		StartTime: time.Now(),
	}
	if cs, ok := conn.(tlsConnectionStater); ok {
		tlsConnState := cs.ConnectionState()
		ri.TLS = &tlsConnState
	}

	ctx = ContextWithRequestInfo(ctx, ri)

	return ctx, cancel
}

// readTCPMsg reads the next incoming DNS message.  If conn is a TLS connection,
// the handshake must have already been performed.  conn must not be nil.
func (s *ServerDNS) readTCPMsg(
	ctx context.Context,
	conn net.Conn,
	timeout time.Duration,
) (msg *dns.Msg, err error) {
	// Use SetReadDeadline as opposed to SetDeadline, since the TLS handshake
	// has already been performed, so conn.Read shouldn't perform writes.
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, fmt.Errorf("setting deadline: %w", err)
	}

	bufPtr := s.tcpPool.Get()
	defer s.tcpPool.Put(bufPtr)

	buf := *bufPtr
	_, err = io.ReadFull(conn, buf[:tcpLengthPrefixSize])
	if err != nil {
		return nil, fmt.Errorf("reading length: %w", err)
	}

	length := int(binary.BigEndian.Uint16(buf[:tcpLengthPrefixSize]))
	if cap(buf) < length {
		buf = slices.Grow(buf, length-len(buf))
		*bufPtr = buf
	}

	_, err = io.ReadFull(conn, buf[:length])
	if err != nil {
		return nil, fmt.Errorf("reading message: %w", err)
	}

	req := &dns.Msg{}
	err = req.Unpack(buf[:length])
	if err != nil {
		s.metrics.OnInvalidMsg(ctx)

		return nil, fmt.Errorf("unpacking message: %w", err)
	}

	return req, nil
}
