package dnsserver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// serveTCP runs the TCP serving loop.
func (s *ServerDNS) serveTCP(ctx context.Context, l net.Listener) (err error) {
	defer log.OnCloserError(l, log.DEBUG)

	for s.isStarted() {
		var conn net.Conn
		conn, err = l.Accept()
		// Check the error code and exit loop if necessary
		if err != nil {
			if !s.isStarted() {
				return nil
			}

			if isNonCriticalNetError(err) {
				// Non-critical errors, do not register in the metrics or log
				// anywhere.
				continue
			}

			return err
		}

		s.tcpConnsMu.Lock()
		// Track the connection to allow unblocking reads on shutdown.
		s.tcpConns[conn] = struct{}{}
		s.tcpConnsMu.Unlock()

		s.wg.Add(1)

		go s.serveTCPConn(ctx, conn)
	}

	return nil
}

// serveTCPConn serves a single TCP connection.
func (s *ServerDNS) serveTCPConn(ctx context.Context, conn net.Conn) {
	// we use this to wait until all queries from this connection
	// has been processed before closing the connection
	tcpWg := sync.WaitGroup{}
	defer func() {
		tcpWg.Wait()
		log.OnCloserError(conn, log.DEBUG)
		s.tcpConnsMu.Lock()
		delete(s.tcpConns, conn)
		s.tcpConnsMu.Unlock()
		s.wg.Done()
	}()
	defer s.handlePanicAndRecover(ctx)

	timeout := s.conf.ReadTimeout
	idleTimeout := s.conf.TCPIdleTimeout

	for s.isStarted() {
		m, err := s.readTCPMsg(conn, timeout)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				// Don't even log these.
				return
			}

			// No need to read further.
			log.Debug(
				"[%s]: Failed to read message from a NetworkTCP connection: %v",
				s.Name(),
				err,
			)

			return
		}

		// RFC 7766 recommends implementing query pipelining, i.e.
		// process all incoming queries concurrently and write responses
		// out of order.
		tcpWg.Add(1)

		reqCtx := s.requestContext()

		ci := ClientInfo{}
		if cs, ok := conn.(tlsConnectionStater); ok {
			ci.TLSServerName = strings.ToLower(cs.ConnectionState().ServerName)
		}
		reqCtx = ContextWithClientInfo(reqCtx, ci)

		go s.serveTCPMessage(reqCtx, &tcpWg, m, conn)

		// use idle timeout for next queries
		timeout = idleTimeout
	}
}

// tlsConnectionStater is a common interface for connections that can return
// a TLS connection state.
type tlsConnectionStater interface {
	ConnectionState() tls.ConnectionState
}

// serveTCPMessage processes a single TCP message.
func (s *ServerDNS) serveTCPMessage(
	ctx context.Context,
	wg *sync.WaitGroup,
	m []byte,
	conn net.Conn,
) {
	defer wg.Done()
	defer s.handlePanicAndRecover(ctx)

	rw := &tcpResponseWriter{
		conn:         conn,
		writeTimeout: s.conf.WriteTimeout,
	}
	written := s.serveDNS(ctx, m, rw)
	s.putTCPBuffer(m)

	if !written {
		// Nothing has been written, we should close the connection in order to
		// avoid hanging connections.  Than might happen if the handler
		// rate-limited connections or if we received garbage data instead of
		// a DNS query.
		log.OnCloserError(conn, log.DEBUG)
	}
}

// readTCPMsg reads the next incoming DNS message.
func (s *ServerDNS) readTCPMsg(conn net.Conn, timeout time.Duration) ([]byte, error) {
	err := conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, err
	}

	var length uint16
	if err = binary.Read(conn, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	m := s.getTCPBuffer(int(length))
	if _, err = io.ReadFull(conn, m); err != nil {
		s.putTCPBuffer(m)
		return nil, err
	}

	return m, nil
}

// getTCPBuffer gets a TCP buffer to be used to read the incoming DNS query
// length - the desired TCP buffer length.
func (s *ServerDNS) getTCPBuffer(length int) (buff []byte) {
	if length > s.conf.TCPSize {
		// If the query is larger than the buffer size
		// don't use sync.Pool at all, just allocate a new array
		return make([]byte, length)
	}

	m := *s.tcpPool.Get().(*[]byte)

	return m[:length]
}

// putTCPBuffer puts the TCP buffer back to pool.
func (s *ServerDNS) putTCPBuffer(m []byte) {
	if cap(m) != s.conf.TCPSize {
		// This slice was not got from pool, ignore it
		return
	}

	if len(m) != s.conf.TCPSize {
		// Means a new slice was created (see ServerDNS.getTCPBuffer)
		// We should create a new slice with the proper size before
		// putting it back to pool
		m = m[:s.conf.TCPSize]
	}

	s.tcpPool.Put(&m)
}

// tcpResponseWriter implements ResponseWriter interface for a DNS-over-TCP or
// a DNS-over-TLS server.
type tcpResponseWriter struct {
	conn         net.Conn
	writeTimeout time.Duration
}

// type check
var _ ResponseWriter = (*tcpResponseWriter)(nil)

// LocalAddr implements the ResponseWriter interface for *tcpResponseWriter.
func (r *tcpResponseWriter) LocalAddr() (addr net.Addr) {
	return r.conn.LocalAddr()
}

// RemoteAddr implements the ResponseWriter interface for *tcpResponseWriter.
func (r *tcpResponseWriter) RemoteAddr() (addr net.Addr) {
	return r.conn.RemoteAddr()
}

// WriteMsg implements the ResponseWriter interface for *tcpResponseWriter.
func (r *tcpResponseWriter) WriteMsg(ctx context.Context, req, resp *dns.Msg) (err error) {
	normalize(NetworkTCP, req, resp)

	var msg []byte
	msg, err = packWithPrefix(resp)
	if err != nil {
		return fmt.Errorf("tcp: packing response: %w", err)
	}

	withWriteDeadline(ctx, r.writeTimeout, r.conn, func() {
		_, err = r.conn.Write(msg)
	})

	if err != nil {
		return &WriteError{
			Err:      err,
			Protocol: "tcp",
		}
	}

	return nil
}
