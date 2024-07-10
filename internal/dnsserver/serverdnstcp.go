package dnsserver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

// serveTCP runs the TCP serving loop.
func (s *ServerDNS) serveTCP(ctx context.Context, l net.Listener) (err error) {
	defer log.OnCloserError(l, log.DEBUG)

	for s.isStarted() {
		err = s.acceptTCPConn(ctx, l)
		if err != nil {
			if !s.isStarted() {
				return nil
			}

			return err
		}
	}

	return nil
}

// acceptTCPConn reads and starts processing a single TCP connection.
//
// NOTE: Any error returned from this method stops handling on l.
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
	// Don't defer the close because it's deferred in serveTCPConn.

	func() {
		s.tcpConnsMu.Lock()
		defer s.tcpConnsMu.Unlock()

		// Track the connection to allow unblocking reads on shutdown.
		s.tcpConns[conn] = struct{}{}
	}()

	s.wg.Add(1)

	return s.workerPool.Submit(func() {
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

// serveTCPConn serves a single TCP connection.
func (s *ServerDNS) serveTCPConn(ctx context.Context, conn net.Conn) {
	// Use this to wait until all queries from this connection has been
	// processed before closing it.
	wg := &sync.WaitGroup{}

	defer func() {
		defer s.wg.Done()

		wg.Wait()

		log.OnCloserError(conn, log.DEBUG)

		s.tcpConnsMu.Lock()
		defer s.tcpConnsMu.Unlock()

		delete(s.tcpConns, conn)
	}()

	defer s.handlePanicAndRecover(ctx)

	var msgSema syncutil.Semaphore = syncutil.EmptySemaphore{}
	if s.conf.MaxPipelineEnabled {
		msgSema = syncutil.NewChanSemaphore(s.conf.MaxPipelineCount)
	}

	// writeMu serializes write deadline setting and writing to conn.
	writeMu := &sync.Mutex{}

	timeout := s.conf.ReadTimeout
	idleTimeout := s.conf.TCPIdleTimeout

	err := handshake(conn, timeout)
	if err != nil {
		s.logReadErr("handshaking", err)

		return
	}

	for s.isStarted() {
		err = s.acceptTCPMsg(conn, wg, writeMu, timeout, msgSema)
		if err != nil {
			s.logReadErr("reading from conn", err)

			return
		}

		// Use idle timeout for further queries.
		timeout = idleTimeout
	}
}

// logReadErr logs err on debug level unless it's trivial ([io.EOF] or
// [net.ErrClosed]).
func (s *ServerDNS) logReadErr(msg string, err error) {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return
	}

	log.Debug("[%s]: %s: %s", s.Name(), msg, err)
}

// acceptTCPMsg reads and starts processing a single TCP message.  If conn is a
// TLS connection, the handshake must have already been performed.
func (s *ServerDNS) acceptTCPMsg(
	conn net.Conn,
	wg *sync.WaitGroup,
	writeMu *sync.Mutex,
	timeout time.Duration,
	msgSema syncutil.Semaphore,
) (err error) {
	bufPtr, err := s.readTCPMsg(conn, timeout)
	if err != nil {
		return err
	}

	// RFC 7766 recommends implementing query pipelining, i.e. process all
	// incoming queries concurrently and write responses out of order.
	wg.Add(1)

	ri := &RequestInfo{
		StartTime: time.Now(),
	}
	if cs, ok := conn.(tlsConnectionStater); ok {
		ri.TLSServerName = cs.ConnectionState().ServerName
	}

	reqCtx, reqCancel := s.requestContext()
	reqCtx = ContextWithRequestInfo(reqCtx, ri)

	err = msgSema.Acquire(reqCtx)
	if err != nil {
		return fmt.Errorf("waiting for sema: %w", err)
	}

	return s.workerPool.Submit(func() {
		defer reqCancel()
		defer msgSema.Release()

		s.serveTCPMessage(reqCtx, wg, writeMu, *bufPtr, conn)
		s.tcpPool.Put(bufPtr)
	})
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
	writeMu *sync.Mutex,
	buf []byte,
	conn net.Conn,
) {
	defer wg.Done()
	defer s.handlePanicAndRecover(ctx)

	rw := &tcpResponseWriter{
		respPool:     s.respPool,
		writeMu:      writeMu,
		conn:         conn,
		writeTimeout: s.conf.WriteTimeout,
		idleTimeout:  s.conf.TCPIdleTimeout,
	}
	written := s.serveDNS(ctx, buf, rw)

	if !written {
		// Nothing has been written, we should close the connection in order to
		// avoid hanging connections.  Than might happen if the handler
		// rate-limited connections or if we received garbage data instead of
		// a DNS query.
		log.OnCloserError(conn, log.DEBUG)
	}
}

// readTCPMsg reads the next incoming DNS message.  If conn is a TLS connection,
// the handshake must have already been performed.
func (s *ServerDNS) readTCPMsg(conn net.Conn, timeout time.Duration) (bufPtr *[]byte, err error) {
	// Use SetReadDeadline as opposed to SetDeadline, since the TLS handshake
	// has already been performed, so conn.Read shouldn't perform writes.
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, err
	}

	var length uint16
	if err = binary.Read(conn, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	bufPtr = s.getTCPBuffer(int(length))
	_, err = io.ReadFull(conn, *bufPtr)
	if err != nil {
		s.tcpPool.Put(bufPtr)

		return nil, err
	}

	return bufPtr, nil
}

// getTCPBuffer returns a TCP buffer to be used to read the incoming DNS query
// with the given length.
func (s *ServerDNS) getTCPBuffer(length int) (bufPtr *[]byte) {
	bufPtr = s.tcpPool.Get()

	buf := *bufPtr
	if l := len(buf); l < length {
		buf = slices.Grow(buf, length-l)
	}

	buf = buf[:length]
	*bufPtr = buf

	return bufPtr
}

// tcpResponseWriter implements ResponseWriter interface for a DNS-over-TCP or
// a DNS-over-TLS server.
type tcpResponseWriter struct {
	respPool *syncutil.Pool[[]byte]
	// writeMu is used to serialize the sequence of setting the write deadline,
	// writing to a connection, and resetting the write deadline, across
	// multiple goroutines in the pipeline.
	writeMu      *sync.Mutex
	conn         net.Conn
	writeTimeout time.Duration
	idleTimeout  time.Duration
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
	si := MustServerInfoFromContext(ctx)
	normalizeTCP(si.Proto, req, resp)
	r.addTCPKeepAlive(req, resp)

	bufPtr := r.respPool.Get()
	defer func() {
		if err != nil {
			r.respPool.Put(bufPtr)
		}
	}()

	b, err := packWithPrefix(resp, *bufPtr)
	if err != nil {
		return fmt.Errorf("tcp: packing response: %w", err)
	}

	*bufPtr = b

	// Serialize the write deadline setting on the shared connection, since
	// messages accepted over TCP are processed out of order.
	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	// Use SetWriteDeadline as opposed to SetDeadline, since the TLS handshake
	// has already been performed, so conn.Write shouldn't perform reads.
	withWriteDeadline(ctx, r.writeTimeout, r.conn, func() {
		_, err = r.conn.Write(b)
	})

	if err != nil {
		return &WriteError{
			Err:      err,
			Protocol: "tcp",
		}
	}

	return nil
}

// addTCPKeepAlive adds a ENDS0 TCP keep-alive option to the DNS response
// as per RFC 7828.  This option specifies the desired idle connection timeout.
func (r *tcpResponseWriter) addTCPKeepAlive(req, resp *dns.Msg) {
	reqOpt := req.IsEdns0()
	respOpt := resp.IsEdns0()

	if reqOpt == nil ||
		respOpt == nil ||
		findOption[*dns.EDNS0_TCP_KEEPALIVE](reqOpt) == nil {
		// edns-tcp-keepalive can only be added if it's explicitly indicated in
		// the DNS request that it's supported.
		return
	}

	keepAliveOpt := findOption[*dns.EDNS0_TCP_KEEPALIVE](respOpt)
	if keepAliveOpt == nil {
		keepAliveOpt = &dns.EDNS0_TCP_KEEPALIVE{
			Code: dns.EDNS0TCPKEEPALIVE,
		}
		respOpt.Option = append(respOpt.Option, keepAliveOpt)
	}

	// Should be specified in units of 100 milliseconds encoded in network byte
	// order.
	keepAliveOpt.Timeout = uint16(r.idleTimeout.Milliseconds() / 100)
}
