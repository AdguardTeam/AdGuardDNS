package dnsserver

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// serveUDP runs the UDP serving loop.
func (s *ServerDNS) serveUDP(ctx context.Context, conn net.PacketConn) (err error) {
	defer log.OnCloserError(conn, log.DEBUG)

	for s.isStarted() {
		var m []byte
		var sess netext.PacketSession
		m, sess, err = s.readUDPMsg(ctx, conn)
		if err != nil {
			// TODO(ameshkov): Consider the situation where the server is shut
			// down and restarted between the two calls to isStarted.
			if !s.isStarted() {
				return nil
			}

			if isNonCriticalNetError(err) || errors.Is(err, dns.ErrShortRead) {
				// Non-critical errors, do not register in the metrics or log
				// anywhere.
				continue
			}

			return err
		}

		s.wg.Add(1)

		reqCtx := s.requestContext()
		reqCtx = ContextWithClientInfo(reqCtx, ClientInfo{})

		err = s.workerPool.Submit(func() {
			s.serveUDPPacket(reqCtx, m, conn, sess)
		})
		if err != nil {
			// The workerPool is probably closed, we should exit.
			return err
		}
	}

	return nil
}

// serveUDPPacket serves a new UDP request.
func (s *ServerDNS) serveUDPPacket(
	ctx context.Context,
	m []byte,
	conn net.PacketConn,
	sess netext.PacketSession,
) {
	defer s.wg.Done()
	defer s.handlePanicAndRecover(ctx)

	rw := &udpResponseWriter{
		udpSession:   sess,
		conn:         conn,
		writeTimeout: s.conf.WriteTimeout,
	}
	s.serveDNS(ctx, m, rw)
	s.putUDPBuffer(m)
}

// readUDPMsg reads the next incoming DNS message.
func (s *ServerDNS) readUDPMsg(
	ctx context.Context,
	conn net.PacketConn,
) (msg []byte, sess netext.PacketSession, err error) {
	err = conn.SetReadDeadline(time.Now().Add(s.conf.ReadTimeout))
	if err != nil {
		return nil, nil, err
	}

	m := s.getUDPBuffer()

	n, sess, err := netext.ReadFromSession(conn, m)
	if err != nil {
		s.putUDPBuffer(m)

		return nil, nil, err
	}

	if n < DNSHeaderSize {
		s.metrics.OnInvalidMsg(ctx)
		s.putUDPBuffer(m)

		return nil, nil, dns.ErrShortRead
	}

	// Change the slice size to the message size since the one we got
	// from the buffer is always of UDPSize
	m = m[:n]

	return m, sess, nil
}

// getUDPBuffer gets a buffer to use for reading UDP messages.
func (s *ServerDNS) getUDPBuffer() (buff []byte) {
	return *s.udpPool.Get().(*[]byte)
}

// putUDPBuffer puts the buffer back to pool.
func (s *ServerDNS) putUDPBuffer(m []byte) {
	if len(m) != s.conf.UDPSize {
		// Means a new slice was created (see ServerDNS.readUDPMsg)
		// We should create a new slice with the proper size before
		// putting it back to pool
		m = m[:s.conf.UDPSize]
	}
	s.udpPool.Put(&m)
}

// udpResponseWriter is a ResponseWriter implementation for DNS-over-UDP.
type udpResponseWriter struct {
	udpSession   netext.PacketSession
	conn         net.PacketConn
	writeTimeout time.Duration
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
	normalize(NetworkUDP, ProtoDNS, req, resp)

	var data []byte
	data, err = resp.Pack()
	if err != nil {
		return fmt.Errorf("udp: packing response: %w", err)
	}

	withWriteDeadline(ctx, r.writeTimeout, r.conn, func() {
		_, err = netext.WriteToSession(r.conn, data, r.udpSession)
	})

	if err != nil {
		return &WriteError{
			Err:      err,
			Protocol: "udp",
		}
	}

	return nil
}
