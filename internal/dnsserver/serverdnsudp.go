package dnsserver

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// listenUDP creates a UDP listener for the ServerDNS.addr.
func (s *ServerDNS) listenUDP(ctx context.Context) (err error) {
	l, err := listenUDP(ctx, s.addr)
	if err != nil {
		return err
	}

	u, ok := l.(*net.UDPConn)
	if !ok {
		return ErrInvalidArgument
	}

	if err = setUDPSocketOptions(u); err != nil {
		return err
	}

	s.udpListener = u

	return nil
}

// serveUDP runs the UDP serving loop.
func (s *ServerDNS) serveUDP(ctx context.Context, conn *net.UDPConn) (err error) {
	defer log.OnCloserError(conn, log.DEBUG)

	for s.isStarted() {
		var m []byte
		var sess *dns.SessionUDP
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

		go s.serveUDPPacket(reqCtx, m, conn, sess)
	}

	return nil
}

// serveUDPPacket serves a new UDP request.
func (s *ServerDNS) serveUDPPacket(
	ctx context.Context,
	m []byte,
	conn *net.UDPConn,
	udpSession *dns.SessionUDP,
) {
	defer s.wg.Done()
	defer s.handlePanicAndRecover(ctx)

	rw := &udpResponseWriter{
		conn:         conn,
		udpSession:   udpSession,
		writeTimeout: s.conf.WriteTimeout,
	}
	s.serveDNS(ctx, m, rw)
	s.putUDPBuffer(m)
}

// readUDPMsg reads the next incoming DNS message.
func (s *ServerDNS) readUDPMsg(ctx context.Context, conn *net.UDPConn) (msg []byte, sess *dns.SessionUDP, err error) {
	err = conn.SetReadDeadline(time.Now().Add(s.conf.ReadTimeout))
	if err != nil {
		return nil, nil, err
	}

	m := s.getUDPBuffer()
	var n int
	n, sess, err = dns.ReadFromSessionUDP(conn, m)
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

// setUDPSocketOptions is a function that is necessary to be able to use
// dns.ReadFromSessionUDP and dns.WriteToSessionUDP.
// TODO(ameshkov): https://github.com/AdguardTeam/AdGuardHome/issues/2807
func setUDPSocketOptions(conn *net.UDPConn) (err error) {
	if runtime.GOOS == "windows" {
		return nil
	}

	// We don't know if this a IPv4-only, IPv6-only or a IPv4-and-IPv6 connection.
	// Try enabling receiving of ECN and packet info for both IP versions.
	// We expect at least one of those syscalls to succeed.
	err6 := ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	err4 := ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
	if err4 != nil && err6 != nil {
		return errors.List("error while setting NetworkUDP socket options", err4, err6)
	}

	return nil
}

// udpResponseWriter is a ResponseWriter implementation for DNS-over-UDP.
type udpResponseWriter struct {
	udpSession   *dns.SessionUDP
	conn         *net.UDPConn
	writeTimeout time.Duration
}

// type check
var _ ResponseWriter = (*udpResponseWriter)(nil)

// LocalAddr implements the ResponseWriter interface for *udpResponseWriter.
func (r *udpResponseWriter) LocalAddr() (addr net.Addr) {
	return r.conn.LocalAddr()
}

// RemoteAddr implements the ResponseWriter interface for *udpResponseWriter.
func (r *udpResponseWriter) RemoteAddr() (addr net.Addr) {
	// Don't use r.conn.RemoteAddr(), since udpSession actually contains the
	// decoded OOB data, including the remote address.
	return r.udpSession.RemoteAddr()
}

// WriteMsg implements the ResponseWriter interface for *udpResponseWriter.
func (r *udpResponseWriter) WriteMsg(ctx context.Context, req, resp *dns.Msg) (err error) {
	normalize(NetworkUDP, req, resp)

	var data []byte
	data, err = resp.Pack()
	if err != nil {
		return fmt.Errorf("udp: packing response: %w", err)
	}

	withWriteDeadline(ctx, r.writeTimeout, r.conn, func() {
		_, err = dns.WriteToSessionUDP(r.conn, data, r.udpSession)
	})

	if err != nil {
		return &WriteError{
			Err:      err,
			Protocol: "udp",
		}
	}

	return nil
}
