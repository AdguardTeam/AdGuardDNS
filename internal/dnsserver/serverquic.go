package dnsserver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/bluele/gcache"
	"github.com/miekg/dns"
	"github.com/panjf2000/ants/v2"
	"github.com/quic-go/quic-go"
)

const (
	// nextProtoDoQ is an ALPN token to use for DNS-over-QUIC (DoQ).  During
	// connection establishment, DoQ support is indicated by selecting the ALPN
	// token "doq" in the crypto handshake.
	nextProtoDoQ = "doq"

	// maxQUICIdleTimeout is the maximum QUIC idle timeout.  The default
	// value in quic-go is 30, but our internal tests show that a higher
	// value works better for clients written with ngtcp2.
	maxQUICIdleTimeout = 5 * time.Minute

	// quicAddrValidatorCacheSize is the size of the cache that we use in the QUIC
	// address validator.  The value is chosen arbitrarily and we should consider
	// making it configurable.
	//
	// TODO(ameshkov): make it configurable after we analyze stats.
	quicAddrValidatorCacheSize = 10000

	// quicAddrValidatorCacheTTL is time-to-live for cache items in the QUIC address
	// validator.  The value is chosen arbitrarily and we should consider making it
	// configurable.
	//
	// TODO(ameshkov): make it configurable after we analyze stats.
	quicAddrValidatorCacheTTL = 30 * time.Minute
)

const (
	// DOQCodeNoError is used when the connection or stream needs to be closed,
	// but there is no error to signal.
	DOQCodeNoError = quic.ApplicationErrorCode(0)
	// DOQCodeProtocolError signals that the DoQ implementation encountered
	// a protocol error and is forcibly aborting the connection.
	DOQCodeProtocolError = quic.ApplicationErrorCode(2)
)

// compatProtoDQ are ALPNs for backwards compatibility.
var compatProtoDQ = []string{"doq-i00", "doq-i02", "doq-i03", "dq"}

// ConfigQUIC is a struct that needs to be passed to NewServerQUIC to
// initialize a new ServerQUIC instance.
type ConfigQUIC struct {
	ConfigBase

	// TLSConfig is the TLS configuration for QUIC.
	TLSConfig *tls.Config
}

// ServerQUIC is a DNS-over-QUIC server implementation.
type ServerQUIC struct {
	*ServerBase

	conf ConfigQUIC

	// pool is a goroutine pool we use to process DNS queries.  Complicated
	// logic may require growing the goroutine's stack and we experienced it
	// in AdGuard DNS.  The easiest way to avoid spending extra time on this is
	// to reuse already existing goroutines.
	pool *ants.Pool

	// quicListener is a listener that we use to accept DoQ connections.
	quicListener quic.Listener

	// bytesPool is a pool to avoid unnecessary allocations when reading
	// DNS packets.
	bytesPool sync.Pool
}

// type check
var _ Server = (*ServerQUIC)(nil)

// NewServerQUIC creates a new ServerQUIC instance.
func NewServerQUIC(conf ConfigQUIC) (s *ServerQUIC) {
	// Make sure DOQ ALPNs are enabled in the TLS config.
	tlsConfig := conf.TLSConfig
	if len(tlsConfig.NextProtos) == 0 {
		tlsConfig.NextProtos = append([]string{nextProtoDoQ}, compatProtoDQ...)
	}

	if conf.ListenConfig == nil {
		// Do not enable OOB here as quic-go will do that on its own.
		conf.ListenConfig = netext.DefaultListenConfig()
	}

	s = &ServerQUIC{
		ServerBase: newServerBase(ProtoDoQ, conf.ConfigBase),
		conf:       conf,
		pool:       newPoolNonblocking(),
	}

	return s
}

// Start implements the dnsserver.Server interface for *ServerQUIC.
func (s *ServerQUIC) Start(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "starting doq server: %w") }()

	s.lock.Lock()
	defer s.lock.Unlock()

	if s.conf.TLSConfig == nil {
		return errors.Error("tls config is required")
	}

	if s.started {
		return ErrServerAlreadyStarted
	}
	s.started = true

	log.Info("[%s]: Starting the server", s.name)

	ctx = ContextWithServerInfo(ctx, ServerInfo{
		Name:  s.name,
		Addr:  s.addr,
		Proto: s.proto,
	})

	// Prepare the bytes pool.
	s.bytesPool.New = makePacketBuffer(dns.MaxMsgSize)

	// Start the QUIC listener.
	err = s.listenQUIC(ctx)
	if err != nil {
		return err
	}

	// Run the serving goroutine.
	s.wg.Add(1)
	go s.startServeQUIC(ctx)

	log.Info("[%s]: Server has been started", s.Name())

	return nil
}

// Shutdown implements the dnsserver.Server interface for *ServerQUIC.
func (s *ServerQUIC) Shutdown(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "shutting down doq server: %w") }()

	log.Info("[%s]: Stopping the server", s.Name())

	err = s.shutdown()
	if err != nil {
		log.Info("[%s]: Failed to shutdown: %v", s.Name(), err)

		return err
	}

	err = s.waitShutdown(ctx)

	// Close the workerPool and releases all workers.
	s.pool.Release()

	log.Info("[%s]: Finished stopping the server", s.Name())

	return err
}

// shutdown marks the server as stopped and closes active listeners.
func (s *ServerQUIC) shutdown() (err error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if !s.started {
		return ErrServerNotStarted
	}

	// First, mark it as stopped
	s.started = false

	// Now close all listeners
	s.closeListeners()
	err = s.quicListener.Close()
	if err != nil {
		// Log this error but do not return it
		log.Debug("[%s]: Failed to close QUIC listener: %v", s.Name(), err)
	}

	return nil
}

// startServeQUIC starts the QUIC listener loop.
func (s *ServerQUIC) startServeQUIC(ctx context.Context) {
	// We do not recover from panics here since if this go routine panics
	// the application won't be able to continue listening to DoQ.
	defer s.handlePanicAndExit(ctx)
	defer s.wg.Done()

	log.Info("[%s]: Start listening to quic://%s", s.Name(), s.LocalUDPAddr())
	err := s.serveQUIC(ctx, s.quicListener)
	if err != nil {
		log.Info(
			"[%s]: Finished listening to quic://%s due to %v",
			s.Name(),
			s.LocalUDPAddr(),
			err,
		)
	}
}

// serveQUIC listens for incoming QUIC connections.
func (s *ServerQUIC) serveQUIC(ctx context.Context, l quic.Listener) (err error) {
	connWg := &sync.WaitGroup{}
	// Wait until all conns are processed before exiting this method
	defer connWg.Wait()

	for s.isStarted() {
		var conn quic.Connection
		conn, err = acceptQUICConn(ctx, l)
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

		connWg.Add(1)

		err = s.pool.Submit(func() {
			s.serveQUICConnAsync(ctx, conn, connWg)
		})
		if err != nil {
			// Most likely the workerPool is closed, and we can exit right away.
			// Make sure that the connection is closed just in case.
			closeQUICConn(conn, DOQCodeNoError)

			return err
		}
	}

	return nil
}

// acceptQUICConn is a wrapper around quic.Listener.Accept that makes sure that the
// timeout is handled properly.
func acceptQUICConn(ctx context.Context, l quic.Listener) (conn quic.Connection, err error) {
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(DefaultReadTimeout))
	defer cancel()

	return l.Accept(ctx)
}

// serveQUICConnAsync wraps serveQUICConn call and handles all possible errors
// that might happen there. It also makes sure that the WaitGroup will be
// decremented.
func (s *ServerQUIC) serveQUICConnAsync(
	ctx context.Context,
	conn quic.Connection,
	connWg *sync.WaitGroup,
) {
	defer connWg.Done()
	defer s.handlePanicAndRecover(ctx)

	err := s.serveQUICConn(ctx, conn)
	if !isExpectedQUICErr(err) {
		s.metrics.OnError(ctx, err)
		log.Debug("[%s] Error while serving a QUIC conn: %v", s.Name(), err)
	}
}

// serveQUICConn handles a new QUIC connection. It waits for new streams and
// passes them to serveQUICStream.
func (s *ServerQUIC) serveQUICConn(ctx context.Context, conn quic.Connection) (err error) {
	streamWg := &sync.WaitGroup{}
	defer func() {
		// Wait until all streams are processed.
		streamWg.Wait()

		// Close the connection to make sure resources are freed.
		closeQUICConn(conn, DOQCodeNoError)
	}()

	for s.isStarted() {
		// The stub to resolver DNS traffic follows a simple pattern in which
		// the client sends a query, and the server provides a response.  This
		// design specifies that for each subsequent query on a QUIC connection
		// the client MUST select the next available client-initiated
		// bidirectional stream.
		var stream quic.Stream
		acceptCtx, cancel := context.WithDeadline(ctx, time.Now().Add(maxQUICIdleTimeout))
		stream, err = conn.AcceptStream(acceptCtx)
		// Make sure to call the cancel function to avoid leaks.
		cancel()
		if err != nil {
			return err
		}

		streamWg.Add(1)

		reqCtx := s.requestContext()

		ci := ClientInfo{
			TLSServerName: strings.ToLower(conn.ConnectionState().TLS.ServerName),
		}
		reqCtx = ContextWithClientInfo(reqCtx, ci)

		err = s.pool.Submit(func() {
			s.serveQUICStreamAsync(reqCtx, stream, conn, streamWg)
		})
		if err != nil {
			// The workerPool is closed, we should simply exit.  Make sure that
			// the stream is closed just in case.
			_ = stream.Close()

			return err
		}
	}

	return nil
}

// serveQUICStreamAsync wraps serveQUICStream call and handles all possible
// errors that might happen there. It also makes sure that the WaitGroup will
// be decremented.
func (s *ServerQUIC) serveQUICStreamAsync(
	ctx context.Context,
	stream quic.Stream,
	conn quic.Connection,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	defer s.handlePanicAndRecover(ctx)

	err := s.serveQUICStream(ctx, stream, conn)
	if !isExpectedQUICErr(err) {
		s.metrics.OnError(ctx, err)
		log.Debug("[%s] Failed to process a QUIC stream: %v", s.Name(), err)
	}
}

// serveQUICStream reads DNS queries from the stream, processes them,
// and writes back the responses.
func (s *ServerQUIC) serveQUICStream(
	ctx context.Context,
	stream quic.Stream,
	conn quic.Connection,
) (err error) {
	// The server MUST send the response on the same stream, and MUST indicate
	// through the STREAM FIN mechanism that no further data will be sent on
	// that stream.
	defer log.OnCloserError(stream, log.DEBUG)

	var msg *dns.Msg
	var doqDraft bool
	msg, doqDraft, err = s.readQUICMsg(ctx, stream)
	if err != nil {
		closeQUICConn(conn, DOQCodeProtocolError)

		return err
	}

	if !validQUICMsg(msg) {
		// If a peer encounters such an error condition, it is considered a
		// fatal error. It SHOULD forcibly abort the connection using QUIC's
		// CONNECTION_CLOSE mechanism and SHOULD use the DoQ error code
		// DOQ_PROTOCOL_ERROR.
		closeQUICConn(conn, DOQCodeProtocolError)

		return ErrProtocol
	}

	localAddr := conn.LocalAddr()
	remoteAddr := conn.RemoteAddr()
	rw := NewNonWriterResponseWriter(localAddr, remoteAddr)

	var resp *dns.Msg
	written := s.serveDNSMsg(ctx, msg, rw)
	if !written {
		// Make sure that at least some response has been written
		resp = genErrorResponse(msg, dns.RcodeServerFailure)
	} else {
		resp = rw.Msg()
	}

	// Normalize before writing the response.  Note that for QUIC we can
	// normalize as if it was tcp.
	normalize(NetworkTCP, ProtoDoQ, msg, resp)

	// Depending on the DoQ version we either write a 2-bytes prefixed message
	// or just write the message (for old draft versions).
	var buf []byte
	if doqDraft {
		// TODO(ameshkov): remove draft support in the late 2023.
		buf, err = resp.Pack()
	} else {
		buf, err = packWithPrefix(resp)
	}

	if err != nil {
		closeQUICConn(conn, DOQCodeProtocolError)

		return err
	}

	_, err = stream.Write(buf)

	return err
}

// readQUICMsg reads a DNS query from the QUIC stream and returns an error
// if anything went wrong.
func (s *ServerQUIC) readQUICMsg(
	ctx context.Context,
	stream quic.Stream,
) (m *dns.Msg, doqDraft bool, err error) {
	buf := s.getBuffer()
	defer s.putBuffer(buf)

	// One query - one stream.
	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream.
	_ = stream.SetReadDeadline(time.Now().Add(DefaultReadTimeout))

	// Read the stream data until io.EOF, i.e. until FIN is received.
	var n int
	n, err = readAll(stream, buf)

	// err is not checked here because STREAM FIN sent by the client is
	// indicated as an error here. instead, we should check the number of bytes
	// received.
	if n < DNSHeaderSize {
		if err != nil {
			return nil, false, fmt.Errorf("failed to read QUIC message: %w", err)
		}
		s.metrics.OnInvalidMsg(ctx)

		return nil, false, dns.ErrShortRead
	}

	// Note that we support both the old drafts and the new RFC. In the old
	// draft DNS messages were not prefixed with the message length.
	m = &dns.Msg{}

	// We're checking if the first two bytes contain the length of the message.
	// According to the spec, the DNS message ID is 0 so the first two bytes
	// will be zero in the case of an old draft implementation so this check
	// should be reliable.
	packetLen := binary.BigEndian.Uint16(buf[:2])
	if packetLen == uint16(n-2) {
		err = m.Unpack(buf[2:])
	} else {
		err = m.Unpack(buf)
		doqDraft = true
	}

	if err != nil {
		s.metrics.OnInvalidMsg(ctx)
		return nil, false, err
	}

	return m, doqDraft, nil
}

// readAll reads from r until an error or io.EOF into the specified buffer buf.
// A successful call returns err == nil, not err == io.EOF.  If the buffer is
// too small, it returns error io.ErrShortBuffer.  This function has some
// similarities to io.ReadAll, but it reads to the specified buffer and not
// allocates (and grows) a new one.  Also, it is completely different from
// io.ReadFull as that one reads the exact number of bytes (buffer length) and
// readAll reads until io.EOF or until the buffer is filled.
func readAll(r io.Reader, buf []byte) (n int, err error) {
	for {
		if n == len(buf) {
			return n, io.ErrShortBuffer
		}

		var read int
		read, err = r.Read(buf[n:])
		n += read

		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return n, err
		}
	}
}

// listenQUIC creates the UDP listener for the ServerQUIC.addr and also starts
// the QUIC listener.
func (s *ServerQUIC) listenQUIC(ctx context.Context) (err error) {
	conn, err := s.listenConfig.ListenPacket(ctx, "udp", s.addr)
	if err != nil {
		return err
	}

	qConf := newServerQUICConfig(s.metrics)

	// Do not change to quic.ListenEarly, see quicNotEarlyListener to know why.
	ql, err := quic.Listen(conn, s.conf.TLSConfig, qConf)
	if err != nil {
		return err
	}

	s.udpListener = conn
	s.quicListener = ql

	return nil
}

// getBuffer gets a buffer to use for reading DNS messages.
func (s *ServerQUIC) getBuffer() (buff []byte) {
	return *s.bytesPool.Get().(*[]byte)
}

// putBuffer puts the buffer back to the pool.
func (s *ServerQUIC) putBuffer(m []byte) {
	if len(m) != dns.MaxMsgSize {
		// Means a new slice was created
		// We should create a new slice with the proper size before
		// putting it back to pool
		m = m[:dns.MaxMsgSize]
	}
	s.bytesPool.Put(&m)
}

// isExpectedQUICErr checks if this error signals about closing QUIC connection,
// stream, or server and if it's expected and does not require any recovery or
// additional processing.
//
// TODO(a.garipov): Move fully or partially to the main module.
func isExpectedQUICErr(err error) (ok bool) {
	if err == nil {
		return true
	}

	// Expected to be returned by all streams and connection methods calls when
	// the server is closed.  Unfortunately, this error is not exported from
	// quic-go.
	if errors.Is(err, quic.ErrServerClosed) {
		return true
	}

	// Catch quic-go's IdleTimeoutError.  This error is returned from
	// quic.Connection.AcceptStream calls and this is an expected outcome,
	// happens all the time with different QUIC clients.
	var qErr *quic.IdleTimeoutError
	if errors.As(err, &qErr) {
		return true
	}

	// Catch quic-go's ApplicationError with error code 0.  This error is
	// returned from quic-go methods when the client closes the connection.
	// This is an expected situation, and it's not necessary to log it.
	var qAppErr *quic.ApplicationError
	if errors.As(err, &qAppErr) && qAppErr.ErrorCode == 0 {
		return true
	}

	// Catch a network timeout error.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// Catch EOF, which is returned when the client sends stream FIN alongside
	// with data.  Can be safely ignored, it just means that the stream is
	// closed.
	if !errors.Is(err, io.EOF) {
		return true
	}

	// Catch some common timeout and net errors.
	return !errors.Is(err, context.DeadlineExceeded) &&
		!errors.Is(err, net.ErrClosed)
}

// validQUICMsg validates the incoming DNS message and returns false if
// something is wrong with the message.
func validQUICMsg(req *dns.Msg) (ok bool) {
	// See https://www.rfc-editor.org/rfc/rfc9250.html#name-protocol-errors

	// 1. a client or server receives a message with a non-zero Message ID.
	//
	// We do consciously not validate this case since there are stub proxies
	// that are sending a non-zero Message IDs.

	// 2. a client or server receives a STREAM FIN before receiving all the
	// bytes for a message indicated in the 2-octet length field.
	// 3. a server receives more than one query on a stream
	//
	// These cases are covered earlier when unpacking the DNS message.

	// 4. the client or server does not indicate the expected STREAM FIN after
	// sending requests or responses (see Section 4.2).
	//
	// This is quite problematic to validate this case since this would imply
	// we have to wait until STREAM FIN is arrived before we start processing
	// the message. So we're consciously ignoring this case in this
	// implementation.

	// 5. an implementation receives a message containing the edns-tcp-keepalive
	// EDNS(0) Option [RFC7828] (see Section 5.5.2).
	if opt := req.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			// Check for EDNS TCP keepalive option
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				return false
			}
		}
	}

	// 6. a client or a server attempts to open a unidirectional QUIC stream.
	//
	// This case can only be handled when writing a response.

	// 7. a server receives a "replayable" transaction in 0-RTT data
	//
	// The information necessary to validate this is not exposed by quic-go.

	return true
}

// closeQUICConn quietly closes the QUIC connection with the specified error
// code and logs if it fails to close the connection.
func closeQUICConn(conn quic.Connection, code quic.ApplicationErrorCode) {
	err := conn.CloseWithError(code, "")
	if err != nil {
		log.Debug("failed to close the QUIC connection: %v", err)
	}
}

// newServerQUICConfig creates *quic.Config populated with the default settings.
// This function is supposed to be used for both DoQ and DoH3 server.
func newServerQUICConfig(metrics MetricsListener) (conf *quic.Config) {
	v := newQUICAddrValidator(quicAddrValidatorCacheSize, quicAddrValidatorCacheTTL, metrics)

	return &quic.Config{
		MaxIdleTimeout:           maxQUICIdleTimeout,
		MaxIncomingStreams:       math.MaxUint16,
		MaxIncomingUniStreams:    math.MaxUint16,
		RequireAddressValidation: v.requiresValidation,
		// Enable 0-RTT by default for all addresses, it's beneficial for the
		// performance.
		Allow0RTT: func(net.Addr) (ok bool) {
			return true
		},
	}
}

// quicAddrValidator is a helper struct that holds a small LRU cache of
// addresses for which we do not require address validation.
type quicAddrValidator struct {
	cache   gcache.Cache
	ttl     time.Duration
	metrics MetricsListener
}

// newQUICAddrValidator initializes a new instance of *quicAddrValidator.
func newQUICAddrValidator(
	cacheSize int,
	ttl time.Duration,
	metrics MetricsListener,
) (v *quicAddrValidator) {
	return &quicAddrValidator{
		cache:   gcache.New(cacheSize).LRU().Build(),
		ttl:     ttl,
		metrics: metrics,
	}
}

// requiresValidation determines if a QUIC Retry packet should be sent by the
// client. This allows the server to verify the client's address but increases
// the latency.
//
// TODO(ameshkov): consider caddy-like implementation here.
func (v *quicAddrValidator) requiresValidation(addr net.Addr) (ok bool) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		// Report this as an error as this is not the expected behavior here.
		v.metrics.OnError(
			context.Background(),
			fmt.Errorf("not a udp address: %v", addr),
		)

		return false
	}

	key := udpAddr.IP.String()
	if v.cache.Has(key) {
		v.metrics.OnQUICAddressValidation(true)

		return false
	}

	v.metrics.OnQUICAddressValidation(false)

	err := v.cache.SetWithExpire(key, true, v.ttl)
	if err != nil {
		// Shouldn't happen, since we don't set a serialization function.
		panic(fmt.Errorf("quic validator: setting cache item: %w", err))
	}

	// Address not found in the cache so return true to make sure the server
	// will require address validation.
	return true
}
