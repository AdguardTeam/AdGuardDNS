package dnsserver

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/bluele/gcache"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

const (
	// nextProtoDoQ is an ALPN token to use for DNS-over-QUIC (DoQ).  During
	// connection establishment, DoQ support is indicated by selecting the ALPN
	// token "doq" in the crypto handshake.
	nextProtoDoQ = "doq"

	// maxQUICIdleTimeout is the maximum QUIC idle timeout.  The default value
	// in quic-go is 30, but our internal tests show that a higher value works
	// better for clients written with ngtcp2.
	maxQUICIdleTimeout = 5 * time.Minute

	// quicDefaultMaxStreamsPerPeer is the default maximum number of QUIC
	// concurrent streams that a peer is allowed to open.
	quicDefaultMaxStreamsPerPeer = 100

	// quicAddrValidatorCacheSize is the size of the cache that we use in the
	// QUIC address validator.  The value is chosen arbitrarily and we should
	// consider making it configurable.
	//
	// TODO(ameshkov): make it configurable after we analyze stats.
	quicAddrValidatorCacheSize = 10000

	// quicAddrValidatorCacheTTL is time-to-live for cache items in the QUIC
	// address validator.  The value is chosen arbitrarily and we should
	// consider making it configurable.
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

// NextProtoDoQ is a list of ALPN protocols added by default to the server's
// *tls.Config if no NextProto is specified there and DoQ is supposed to be
// used.
var NextProtoDoQ = append([]string{nextProtoDoQ}, compatProtoDQ...)

// ConfigQUIC is a struct that needs to be passed to NewServerQUIC to
// initialize a new ServerQUIC instance.
type ConfigQUIC struct {
	// TLSConfig is the TLS configuration for QUIC.  If it is not nil, it must
	// be set to [NextProtoDoQ].
	TLSConfig *tls.Config

	// Base is the base configuration for this server.  It must not be nil and
	// must be valid.
	Base *ConfigBase

	// MaxStreamsPerPeer is the maximum number of concurrent streams that a peer
	// is allowed to open.  If not set, 100 is used.
	MaxStreamsPerPeer int

	// QUICLimitsEnabled, if true, enables QUIC limiting.
	QUICLimitsEnabled bool
}

// ServerQUIC is a DNS-over-QUIC server implementation.
//
// TODO(a.garipov):  Consider unembedding ServerBase.
type ServerQUIC struct {
	*ServerBase

	// taskPool is a goroutine pool used to process DNS queries.  It is used to
	// prevent excessive growth of goroutine stacks.
	taskPool *taskPool

	// reqPool is a pool to avoid unnecessary allocations when reading
	// DNS packets.
	reqPool *syncutil.Pool[[]byte]

	// respPool is a pool for response buffers.
	respPool *syncutil.Pool[[]byte]

	// quicListener is a listener that we use to accept DoQ connections.
	quicListener *quic.Listener

	// transport is the QUIC transport saved here to close it later.
	transport *quic.Transport

	tlsConf *tls.Config

	maxStreamsPerPeer int

	quicLimitsEnabled bool
}

// quicBytePoolSize is the size for the QUIC byte pools.
const quicBytePoolSize = dns.MaxMsgSize

// NewServerQUIC creates a new ServerQUIC instance.  c must not be nil and must
// be valid.
func NewServerQUIC(c *ConfigQUIC) (s *ServerQUIC) {
	// Do not enable OOB here as quic-go will do that on its own.
	c.Base.ListenConfig = cmp.Or(c.Base.ListenConfig, netext.DefaultListenConfig(nil))

	s = &ServerQUIC{
		ServerBase: newServerBase(ProtoDoQ, c.Base),
		reqPool:    syncutil.NewSlicePool[byte](quicBytePoolSize),
		respPool:   syncutil.NewSlicePool[byte](quicBytePoolSize),
		tlsConf:    c.TLSConfig,
		// NOTE:  100 is the current default in package quic, but set it
		// explicitly in case that changes in the future.
		maxStreamsPerPeer: cmp.Or(c.MaxStreamsPerPeer, 100),
		quicLimitsEnabled: c.QUICLimitsEnabled,
	}

	s.taskPool = mustNewTaskPool(&taskPoolConfig{
		logger: s.baseLogger,
	})

	return s
}

// type check
var _ Server = (*ServerQUIC)(nil)

// Start implements the [Server] interface for *ServerQUIC.
func (s *ServerQUIC) Start(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "starting doq server: %w") }()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return ErrServerAlreadyStarted
	}

	s.baseLogger.InfoContext(ctx, "starting server")

	ctx = ContextWithServerInfo(ctx, &ServerInfo{
		Name:  s.name,
		Addr:  s.addr,
		Proto: s.proto,
	})

	// Start the QUIC listener.
	err = s.listenQUIC(ctx)
	if err != nil {
		return err
	}

	s.activeTaskWG.Go(func() {
		s.serveQUIC(ctx, s.quicListener)
	})

	s.started = true

	s.baseLogger.InfoContext(ctx, "server has been started")

	return nil
}

// Shutdown implements the [Server] interface for *ServerQUIC.
func (s *ServerQUIC) Shutdown(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "shutting down doq server: %w") }()

	s.baseLogger.InfoContext(ctx, "shutting down server")

	err = s.shutdown(ctx)
	if err != nil {
		s.baseLogger.WarnContext(ctx, "error while shutting down", slogutil.KeyError, err)

		return err
	}

	err = s.waitShutdown(ctx)

	// Close the taskPool and release all workers.
	s.taskPool.Release()

	s.baseLogger.InfoContext(ctx, "server has been shut down")

	return err
}

// shutdown marks the server as stopped and closes active listeners.
func (s *ServerQUIC) shutdown(ctx context.Context) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		return ErrServerNotStarted
	}

	// First, mark it as stopped
	s.started = false

	// Now close all listeners.
	err = s.quicListener.Close()
	if err != nil {
		s.baseLogger.DebugContext(ctx, "closing quic listener", slogutil.KeyError, err)
	}

	// And the transport.
	err = s.transport.Close()
	if err != nil {
		s.baseLogger.DebugContext(ctx, "closing quic transport", slogutil.KeyError, err)
	}

	return nil
}

// serveQUIC listens for incoming QUIC connections.
func (s *ServerQUIC) serveQUIC(ctx context.Context, l *quic.Listener) {
	// We do not recover from panics here since if this go routine panics
	// the application won't be able to continue listening to DoQ.
	defer s.handlePanicAndExit(ctx)

	s.baseLogger.InfoContext(ctx, "starting listening quic")

	wg := &sync.WaitGroup{}
	defer wg.Wait()

	// Use a context that is canceled once this connection ends to mitigate
	// quic-go's mishandling of contexts.  See the TODO in
	// [ServerQUIC.serveQUICConn].
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for s.isStarted() {
		err := s.acceptQUICConn(ctx, l, wg)
		if err == nil {
			continue
		}

		// TODO(ameshkov):  Consider the situation where the server is shut down
		// and restarted between the two calls to isStarted.
		if !s.isStarted() {
			s.baseLogger.DebugContext(
				ctx,
				"listening quic failed: server not started",
				slogutil.KeyError, err,
			)
		} else {
			s.baseLogger.ErrorContext(ctx, "listening quic failed", slogutil.KeyError, err)
		}

		return
	}
}

// acceptQUICConn reads and starts processing a single QUIC connection.
//
// NOTE:  Any error returned from this method stops handling on l.
func (s *ServerQUIC) acceptQUICConn(
	ctx context.Context,
	l *quic.Listener,
	wg *sync.WaitGroup,
) (err error) {
	acceptCtx, cancel := context.WithDeadline(ctx, time.Now().Add(DefaultReadTimeout))
	defer cancel()

	conn, err := l.Accept(acceptCtx)
	if err != nil {
		if isNonCriticalNetError(err) {
			// Non-critical errors, do not register in the metrics or log
			// anywhere.
			return nil
		}

		return err
	}

	err = s.taskPool.submitWG(wg, func() {
		defer s.handlePanicAndRecover(ctx)

		s.serveQUICConn(ctx, conn)
	})
	if err != nil {
		// Most likely the taskPool is closed.  Exit and make sure that the
		// connection is closed just in case.
		s.closeQUICConn(ctx, conn, DOQCodeNoError)

		return err
	}

	return nil
}

// isReportableQUICStreamError is a helper that returns true if err is network
// error that should be reported when it arises from a stream.  If err is nil,
// ok is false.
func isReportableQUICStreamError(err error) (ok bool) {
	if err == nil {
		return false
	}

	if isNonCriticalNetError(err) {
		return false
	}

	var readErr *quicReadError
	if errors.As(err, &readErr) {
		return false
	}

	// [quic.ApplicationError.Unwrap] always returns [net.ErrClosed].
	return !errors.Is(err, net.ErrClosed)
}

// serveQUICConn handles a new QUIC connection.  It waits for new streams and
// passes them to [serveQUICStream].
func (s *ServerQUIC) serveQUICConn(ctx context.Context, conn *quic.Conn) {
	var err error
	defer func() {
		if isReportableQUICStreamError(err) {
			s.metrics.OnError(ctx, err)
			s.baseLogger.DebugContext(ctx, "serving quic conn", slogutil.KeyError, err)
		}
	}()

	streamWg := &sync.WaitGroup{}

	doqCode := DOQCodeNoError
	defer func() {
		streamWg.Wait()
		s.closeQUICConn(ctx, conn, doqCode)
	}()

	for s.isStarted() {
		var stream *quic.Stream
		stream, err = s.acceptStream(ctx, conn)
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return
		}

		doqCode, err = s.serveQUICStream(ctx, conn, stream, streamWg)
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return
		}
	}
}

// serveQUICStream serves a single QUIC stream.  All arguments must not be nil.
//
// TODO(a.garipov):  Audit the error conditions in this method and optimize for
// fewer unnecessary connection breaks.
//
// NOTE:  Any error returned from this method stops handling on conn.
func (s *ServerQUIC) serveQUICStream(
	parent context.Context,
	conn *quic.Conn,
	stream *quic.Stream,
	wg *sync.WaitGroup,
) (errCode quic.ApplicationErrorCode, err error) {
	ctx, cancel := s.newContextForQUICReq(parent, conn)
	defer func() { callOnError(cancel, recover(), err) }()

	req, err := s.readQUICMsg(ctx, stream)
	if err != nil {
		return DOQCodeProtocolError, fmt.Errorf("reading quic message: %w", err)
	}

	rw := s.newQUICRW(conn, stream)
	err = s.acquireSema(ctx, s.activeRequestsSema, req, rw, errMsgActiveReqSema)
	if err != nil {
		// Don't return the error to not close the connection.
		return DOQCodeNoError, nil
	}
	defer func() { callOnError(s.activeRequestsSema.Release, recover(), err) }()

	err = s.taskPool.submitWG(wg, func() {
		defer s.handlePanicAndRecover(ctx)
		defer cancel()
		defer s.activeRequestsSema.Release()

		// The server MUST send the response on the same stream, and MUST
		// indicate through the STREAM FIN mechanism that no further data will
		// be sent on that stream.
		defer slogutil.CloseAndLog(ctx, s.baseLogger, stream, slog.LevelDebug)

		_ = s.serveDNSMsg(ctx, req, rw)
	})
	if err != nil {
		// Most likely the taskPool is closed.  Exit and make sure that the
		// stream is closed just in case.
		return DOQCodeNoError, errors.WithDeferred(err, stream.Close())
	}

	return DOQCodeNoError, nil
}

// newContextForQUICReq returns a new context for a QUIC request.  All arguments
// must not be nil.
func (s *ServerQUIC) newContextForQUICReq(
	parent context.Context,
	conn *quic.Conn,
) (ctx context.Context, cancel context.CancelFunc) {
	ctx, cancel = s.reqCtx.New(context.WithoutCancel(parent))
	tlsConnState := conn.ConnectionState().TLS
	ctx = ContextWithRequestInfo(ctx, &RequestInfo{
		TLS:       &tlsConnState,
		StartTime: time.Now(),
	})

	return ctx, cancel
}

// quicReadError is returned from [ServerQUIC.readQUICMsg].
//
// TODO(a.garipov):  Improve error handling and consider removing this.
type quicReadError struct {
	err error
}

// type check
var _ error = (*quicReadError)(nil)

// Error implements the [error] interface for *quicReadError.
func (err *quicReadError) Error() (msg string) {
	return fmt.Sprintf("reading quic message: %s", err.err)
}

// type check
var _ errors.Wrapper = (*quicReadError)(nil)

// Error implements the [errors.Wrapper] interface for *quicReadError.
func (err *quicReadError) Unwrap() (unwrapped error) {
	return err.err
}

// readQUICMsg reads a DNS query from the QUIC stream and returns an error if
// anything went wrong.  Any error returned will be of type [*quicReadError].
// All arguments must not be nil.
func (s *ServerQUIC) readQUICMsg(
	ctx context.Context,
	stream *quic.Stream,
) (req *dns.Msg, err error) {
	defer func() {
		if err != nil {
			err = &quicReadError{
				err: err,
			}
		}
	}()

	bufPtr := s.reqPool.Get()
	defer s.reqPool.Put(bufPtr)

	buf := *bufPtr
	buf = buf[:quicBytePoolSize]

	// One query, one stream.  The client MUST send the DNS query over the
	// selected stream, and MUST indicate through the STREAM FIN mechanism that
	// no further data will be sent on that stream.
	err = stream.SetReadDeadline(time.Now().Add(DefaultReadTimeout))
	if err != nil {
		return nil, fmt.Errorf("setting read deadline: %w", err)
	}

	// Read the stream data until io.EOF, i.e. until FIN is received.
	n, err := readAll(stream, buf)

	// err is not checked here because STREAM FIN sent by the client is
	// indicated as an error here.  Instead, check the number of bytes received.
	if n < DNSHeaderSize {
		if err != nil {
			return nil, fmt.Errorf("reading into buffer: %w", err)
		}

		s.metrics.OnInvalidMsg(ctx)

		return nil, dns.ErrShortRead
	}

	// TODO(a.garipov):  DRY the logic with the TCP one.
	req = &dns.Msg{}
	packetLen := binary.BigEndian.Uint16(buf[:2])
	// #nosec G115 -- n has already been checked against DNSHeaderSize.
	wantLen := uint16(n - 2)
	if packetLen == wantLen {
		err = req.Unpack(buf[2:])
	} else {
		err = fmt.Errorf("bad buffer size %d, want %d", packetLen, wantLen)
	}
	if err != nil {
		s.metrics.OnInvalidMsg(ctx)

		return nil, fmt.Errorf("unpacking quic message: %w", err)
	}

	if !validQUICMsg(req) {
		s.metrics.OnInvalidMsg(ctx)

		return nil, ErrProtocol
	}

	return req, nil
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

// newQUICRW returns a new QUIC response writer for a request.  All arguments
// must not be nil.
func (s *ServerQUIC) newQUICRW(conn *quic.Conn, stream *quic.Stream) (rw *quicResponseWriter) {
	return &quicResponseWriter{
		respPool: s.respPool,
		conn:     conn,
		stream:   stream,
		// TODO(a.garipov):  Configure.
		writeTimeout: DefaultWriteTimeout,
	}
}

// acceptStream accepts and starts processing a single QUIC stream.  All
// arguments must not be nil.
//
// NOTE:  Any error returned from this method stops handling on conn.
func (*ServerQUIC) acceptStream(
	parent context.Context,
	conn *quic.Conn,
) (stream *quic.Stream, err error) {
	// The stub to resolver DNS traffic follows a simple pattern in which the
	// client sends a query, and the server provides a response.  This design
	// specifies that for each subsequent query on a QUIC connection the client
	// MUST select the next available client-initiated bidirectional stream.
	ctx, cancel := context.WithDeadline(parent, time.Now().Add(maxQUICIdleTimeout))
	defer cancel()

	// For some reason AcceptStream below seems to get stuck even when ctx is
	// canceled.  As a mitigation, check the context manually right before
	// feeding it into AcceptStream.
	//
	// TODO(a.garipov): Try to reproduce and report.
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("checking accept ctx: %w", ctx.Err())
	default:
		// Go on.
	}

	stream, err = conn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("accepting quic stream: %w", err)
	}

	return stream, nil
}

// listenQUIC creates the UDP listener for the ServerQUIC.addr and also starts
// the QUIC listener.
func (s *ServerQUIC) listenQUIC(ctx context.Context) (err error) {
	conn, err := s.listenConfig.ListenPacket(ctx, "udp", s.addr)
	if err != nil {
		return fmt.Errorf("listening udp for quic: %w", err)
	}

	v := newQUICAddrValidator(quicAddrValidatorCacheSize, s.metrics, quicAddrValidatorCacheTTL)
	transport := &quic.Transport{
		Conn:                conn,
		VerifySourceAddress: v.requiresValidation,
	}

	qConf := newServerQUICConfig(s.quicLimitsEnabled, s.maxStreamsPerPeer)
	ql, err := transport.Listen(s.tlsConf, qConf)
	if err != nil {
		return fmt.Errorf("listening quic: %w", err)
	}

	// Save this for s.LocalUDPAddr.  Do not close it separately as ql closes
	// the underlying connection.
	s.udpListener = conn
	s.transport = transport
	s.quicListener = ql

	return nil
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
func (s *ServerQUIC) closeQUICConn(
	ctx context.Context,
	conn *quic.Conn,
	code quic.ApplicationErrorCode,
) {
	err := conn.CloseWithError(code, "")
	if err != nil {
		s.baseLogger.DebugContext(ctx, "closing quic conn", slogutil.KeyError, err)
	}
}

// newServerQUICConfig creates *quic.Config populated with the default settings.
// This function is supposed to be used for both DoQ and DoH3 server.
func newServerQUICConfig(
	quicLimitsEnabled bool,
	maxStreamsPerPeer int,
) (conf *quic.Config) {
	maxIncStreams := quicDefaultMaxStreamsPerPeer
	maxIncUniStreams := quicDefaultMaxStreamsPerPeer
	if quicLimitsEnabled {
		maxIncStreams = maxStreamsPerPeer
		maxIncUniStreams = maxStreamsPerPeer
	}

	return &quic.Config{
		MaxIdleTimeout:        maxQUICIdleTimeout,
		MaxIncomingStreams:    int64(maxIncStreams),
		MaxIncomingUniStreams: int64(maxIncUniStreams),
		// Enable 0-RTT by default for all addresses, it's beneficial for the
		// performance.
		Allow0RTT: true,
	}
}

// quicAddrValidator is a helper struct that holds a small LRU cache of
// addresses for which we do not require address validation.
type quicAddrValidator struct {
	// TODO(d.kolyshev): Use [agdcache.Default].
	cache   gcache.Cache
	metrics MetricsListener
	ttl     time.Duration
}

// newQUICAddrValidator initializes a new instance of *quicAddrValidator.
func newQUICAddrValidator(
	cacheSize int,
	metrics MetricsListener,
	ttl time.Duration,
) (v *quicAddrValidator) {
	return &quicAddrValidator{
		cache:   gcache.New(cacheSize).LRU().Build(),
		metrics: metrics,
		ttl:     ttl,
	}
}

// requiresValidation determines if a QUIC Retry packet should be sent by the
// client.  This allows the server to verify the client's address but increases
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
