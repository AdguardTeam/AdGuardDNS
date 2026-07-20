package dnsserver

import (
	"context"
	"fmt"
	"net"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
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
		err := s.acceptUDP(ctx, conn)
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
			s.baseLogger.ErrorContext(ctx, "accept udp error", slogutil.KeyError, err)
		}

		return
	}
}

// acceptUDP reads and starts processing a single UDP message.
//
// NOTE:  Any error returned from this method stops handling on conn.
func (s *ServerDNS) acceptUDP(ctx context.Context, conn net.PacketConn) (err error) {
	req, sess, err := s.readUDPMsg(ctx, conn)

	mErr, ok := errors.AsType[*messageFormatError](err)
	if ok {
		// Do not drop requests with valid headers.
		s.baseLogger.DebugContext(ctx, "reading message data", slogutil.KeyError, err)
	} else if err != nil {
		if isNonCriticalNetError(err) || errors.Is(err, dns.ErrShortRead) {
			// Non-critical errors, do not register in the metrics or log
			// anywhere.
			return nil
		}

		return fmt.Errorf("reading udp message: %w", err)
	} else if req == nil {
		// Do not interrupt handling on bad messages.
		return nil
	}

	rw := &udpResponseWriter{
		messageTap:   s.messageTap,
		udpSession:   sess,
		conn:         conn,
		writeTimeout: s.writeTimeout,
		maxRespSize:  s.maxUDPRespSize,
	}

	reqCtx, reqCancel := s.reqCtx.New(context.WithoutCancel(ctx))
	defer func() { callOnError(reqCancel, recover(), err) }()

	reqCtx = ContextWithRequestInfo(reqCtx, &RequestInfo{
		StartTime: s.clock.Now(),
	})

	err = s.acquireSema(reqCtx, s.activeRequestsSema, req, rw, errMsgActiveReqSema)
	if err != nil {
		// Do not interrupt handling on semaphore timeouts.
		return nil
	}
	defer func() { callOnError(s.activeRequestsSema.Release, recover(), err) }()

	// The error returned by submitWG most likely means that the taskPool is
	// closed, so return it to stop handling.
	return s.taskPool.submitWG(s.activeTaskWG, func() {
		defer s.handlePanicAndRecover(ctx)
		defer reqCancel()
		defer s.activeRequestsSema.Release()

		_ = s.serveDNSMsg(reqCtx, req, rw, mErr)
	})
}

// messageFormatError is returned from ServerDNS.readUDPMsg.
type messageFormatError struct {
	// err is the underlying error.
	err error
}

// type check
var _ error = (*messageFormatError)(nil)

// Error implements the error interface for *messageFormatError.
func (err *messageFormatError) Error() (msg string) {
	return fmt.Sprintf("unpacking: %v", err.err)
}

// readUDPMsg reads the next incoming DNS message.  If the message is invalid,
// all req, sess, and err are all nil.  In case message header is valid, it
// returns the req and sess, but the returned err is a [*messageFormatError].
// conn must not be nil.
func (s *ServerDNS) readUDPMsg(
	ctx context.Context,
	conn net.PacketConn,
) (req *dns.Msg, sess netext.PacketSession, err error) {
	err = conn.SetReadDeadline(s.clock.Now().Add(s.readTimeout))
	if err != nil {
		return nil, nil, fmt.Errorf("setting deadline: %w", err)
	}

	bufPtr := s.udpPool.Get()
	defer s.udpPool.Put(bufPtr)

	n, sess, err := netext.ReadFromSession(conn, *bufPtr)
	if err != nil {
		return nil, nil, fmt.Errorf("reading from session: %w", err)
	}

	if n < DNSHeaderSize {
		s.metrics.OnInvalidMsg(ctx)

		return nil, nil, dns.ErrShortRead
	}

	tapRequest(ctx, s.messageTap, sess.LocalAddr(), sess.RemoteAddr(), (*bufPtr)[:n])

	req = &dns.Msg{}
	err = req.Unpack((*bufPtr)[:n])
	if err != nil {
		if req.MsgHdr == (dns.MsgHdr{}) {
			s.metrics.OnInvalidMsg(ctx)

			// Do not interrupt handling on bad messages.
			return nil, nil, nil
		}

		return req, sess, &messageFormatError{
			err: err,
		}
	}

	return req, sess, nil
}
