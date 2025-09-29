package dnsserver

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/contextutil"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

// ConfigBase contains the necessary minimum that every [Server] needs to be
// initialized.
//
// TODO(a.garipov):  Consider splitting and adding appropriate fields to the
// configs of the separate server types.
type ConfigBase struct {
	// BaseLogger is used to create loggers for servers and requests.  It should
	// contain the name of the server.  If BaseLogger is nil, [slog.Default] is
	// used.
	//
	// Loggers for requests derived from this logger include the following
	// fields:
	//   - "qname": the target of the DNS query.
	//   - "qtype": the type of the DNS query.
	//   - "req_id": the 16-bit ID of the message as set by the client.
	BaseLogger *slog.Logger

	// Handler processes incoming DNS messages.  If not set, the default
	// handler, which returns error responses to all queries, is used.
	Handler Handler

	// Metrics is the object we use for collecting performance metrics.  If not
	// set, [EmptyMetricsListener] is used.
	Metrics MetricsListener

	// Disposer is used to help module users reuse parts of DNS responses.  If
	// not set, [EmptyDisposer] is used.
	Disposer Disposer

	// RequestContext is a context constructor that returns contexts for
	// requests.  If not set, the server uses [contextutil.EmptyConstructor].
	RequestContext contextutil.Constructor

	// ListenConfig, when set, is used to set options of connections used by the
	// DNS server.  If nil, an appropriate default ListenConfig is used.
	ListenConfig netext.ListenConfig

	// Network is the network this server listens to.  If empty, the server will
	// listen to all networks that are supposed to be used by the server's
	// protocol.  Note, that it only makes sense for [ServerDNS],
	// [ServerDNSCrypt], and [ServerHTTPS].
	Network Network

	// Name is used for logging, and it may be used for perf counters reporting.
	// It should not be empty.
	Name string

	// Addr is the address the server listens to.  See [net.Dial] for the
	// documentation on the address format.  It must not be empty.
	Addr string
}

// ServerBase implements base methods that every [Server] implementation uses.
type ServerBase struct {
	// baseLogger is the base logger of this server.
	baseLogger *slog.Logger

	// attrPool is the pool of logging attributes for reuse.
	attrPool *syncutil.Pool[[]slog.Attr]

	// handler is a handler that processes incoming DNS messages.
	handler Handler

	// reqCtx is a function that should return the base context.
	reqCtx contextutil.Constructor

	// metrics is the object we use for collecting performance metrics.
	metrics MetricsListener

	// disposer is used to help module users reuse parts of DNS responses.
	disposer Disposer

	// listenConfig is used to set tcpListener and udpListener.
	listenConfig netext.ListenConfig

	// mu protects started, tcpListener, and udpListener.
	mu *sync.RWMutex

	// tcpListener is used to accept new TCP connections.  It is nil for servers
	// that don't use TCP.
	tcpListener net.Listener

	// udpListener is used to accept new UDP messages.  It is nil for servers
	// that don't use UDP.
	udpListener net.PacketConn

	// activeTaskWG tracks goroutines processing UDP and TCP connections and
	// queries.  Shutdown doesn't finish as long as there's at least one active
	// task.
	//
	// TODO(a.garipov):  Consider also using it for listeners.
	activeTaskWG *sync.WaitGroup

	// name is used for logging and it may be used for perf counters reporting.
	//
	// TODO(a.garipov):  Remove eventually.
	name string

	// addr is the address the server listens to.
	addr string

	// network is the network to listen to.  It only makes sense for the
	// following protocols: [ProtoDNS], [ProtoDNSCrypt], [ProtoDoH].
	//
	// TODO(a.garipov):  Move into separate servers.
	network Network

	// proto is the protocol of the server.
	proto Protocol

	// started shows if the server has already been started.
	started bool
}

// type check
var _ Server = (*ServerBase)(nil)

// logAttrNum is the number of attributes used by the request loggers
const logAttrNum = 4

// newServerBase creates a new instance of ServerBase and initializes
// some of its internal properties.  proto must be valid.  c must not be nil.
//
// TODO(a.garipov):  Consider either relaxing the requirements, by turning
// “must” into “should” and returning errors, or validating the configuration
// contracts explicitly.
func newServerBase(proto Protocol, c *ConfigBase) (s *ServerBase) {
	return &ServerBase{
		baseLogger: cmp.Or(c.BaseLogger, slog.Default()),
		attrPool:   syncutil.NewSlicePool[slog.Attr](logAttrNum),
		handler:    cmp.Or[Handler](c.Handler, notImplementedHandlerFunc),
		reqCtx: cmp.Or[contextutil.Constructor](
			c.RequestContext,
			contextutil.EmptyConstructor{},
		),
		metrics:      cmp.Or[MetricsListener](c.Metrics, EmptyMetricsListener{}),
		disposer:     cmp.Or[Disposer](c.Disposer, EmptyDisposer{}),
		listenConfig: c.ListenConfig,
		mu:           &sync.RWMutex{},
		activeTaskWG: &sync.WaitGroup{},
		name:         c.Name,
		addr:         c.Addr,
		network:      c.Network,
		proto:        proto,
	}
}

// Name implements the [Server] interface for *ServerBase.
func (s *ServerBase) Name() (name string) {
	return s.name
}

// Proto implements the [Server] interface for *ServerBase.
func (s *ServerBase) Proto() (proto Protocol) {
	return s.proto
}

// Network implements the [Server] interface for *ServerBase.
func (s *ServerBase) Network() (network Network) {
	return s.network
}

// Addr implements the [Server] interface for *ServerBase.
func (s *ServerBase) Addr() (addr string) {
	return s.addr
}

// Start implements the [Server] interface for *ServerBase.
func (s *ServerBase) Start(_ context.Context) (err error) {
	panic("*ServerBase must not be used directly")
}

// Shutdown implements the [Server] interface for *ServerBase.
func (s *ServerBase) Shutdown(_ context.Context) (err error) {
	panic("*ServerBase must not be used directly")
}

// LocalTCPAddr implements the [Server] interface for *ServerBase.
func (s *ServerBase) LocalTCPAddr() (addr net.Addr) {
	if s.tcpListener != nil {
		return s.tcpListener.Addr()
	}

	return nil
}

// LocalUDPAddr implements the [Server] interface for *ServerBase.
func (s *ServerBase) LocalUDPAddr() (addr net.Addr) {
	if s.udpListener != nil {
		return s.udpListener.LocalAddr()
	}

	return nil
}

// requestContext returns a context for one request and adds server information.
func (s *ServerBase) requestContext(
	parent context.Context,
) (ctx context.Context, cancel context.CancelFunc) {
	ctx, cancel = s.reqCtx.New(parent)
	ctx = ContextWithServerInfo(ctx, &ServerInfo{
		Name:  s.name,
		Addr:  s.addr,
		Proto: s.proto,
	})

	return ctx, cancel
}

// serveDNS processes the incoming DNS query and writes the response to the
// specified ResponseWriter.  written is false if no response was written.
func (s *ServerBase) serveDNS(ctx context.Context, buf []byte, rw ResponseWriter) (written bool) {
	req := &dns.Msg{}
	if err := req.Unpack(buf); err != nil {
		// Ignore the incoming message and let the connection hang as it may be
		// used to amplify.
		s.metrics.OnInvalidMsg(ctx)

		return false
	}

	return s.serveDNSMsg(ctx, req, rw)
}

// serveDNSMsg processes the incoming DNS query and writes the response to the
// specified ResponseWriter.  req and rw must not be nil.  written is false if
// no response was written.
func (s *ServerBase) serveDNSMsg(
	ctx context.Context,
	req *dns.Msg,
	rw ResponseWriter,
) (written bool) {
	attrsPtr := s.newAttrsSlicePtr(req, rw.RemoteAddr().String())
	defer s.attrPool.Put(attrsPtr)

	logHdlr := s.baseLogger.Handler().WithAttrs(*attrsPtr)
	logger := slog.New(logHdlr)

	logger.Log(ctx, slogutil.LevelTrace, "started processing")
	defer logger.Log(ctx, slogutil.LevelTrace, "finished processing")

	ctx = slogutil.ContextWithLogger(ctx, logger)

	recW := NewRecorderResponseWriter(rw)
	s.serveDNSMsgInternal(ctx, logger, req, recW)

	resp := recW.Resp
	written = resp != nil

	var respLen int
	if written {
		// TODO(a.garipov): Use the real number of bytes written by
		// [ResponseWriter] to the socket.
		respLen = resp.Len()
	}

	s.metrics.OnRequest(ctx, &QueryInfo{
		Request:      req,
		RequestSize:  req.Len(),
		Response:     resp,
		ResponseSize: respLen,
	}, rw)

	s.dispose(rw, resp)

	return written
}

// newAttrsSlicePtr returns a pointer to a slice with the attributes from the
// DNS request set.  Callers should defer returning the slice back to the pool.
// req must not be nil.
func (s *ServerBase) newAttrsSlicePtr(req *dns.Msg, raddr string) (attrsPtr *[]slog.Attr) {
	attrsPtr = s.attrPool.Get()

	attrs := *attrsPtr

	// Optimize bounds checking.
	_ = attrs[logAttrNum-1]

	qName, qType := questionData(req)
	attrs[0] = slog.String("qname", qName)
	attrs[1] = slog.String("qtype", qType)
	attrs[2] = slog.String("raddr", raddr)
	attrs[3] = slog.Uint64("req_id", uint64(req.Id))

	return attrsPtr
}

// questionData extracts DNS Question data in a safe manner.  m must not be nil.
func questionData(m *dns.Msg) (hostname, qType string) {
	if len(m.Question) > 0 {
		q := m.Question[0]
		hostname = q.Name
		if v, ok := dns.TypeToString[q.Qtype]; ok {
			qType = v
		} else {
			qType = fmt.Sprintf("TYPE%d", q.Qtype)
		}
	}

	return hostname, qType
}

// dispose is a helper for disposing a DNS response right after writing it to a
// connection.  Disposal of a response is only safe assuming that there is no
// further processing up the stack.  Currently, this is only true for plain DNS
// and DoT at this point in the code.
//
// TODO(a.garipov): Add DoQ as well once the legacy format is removed.
func (s *ServerBase) dispose(rw ResponseWriter, resp *dns.Msg) {
	switch rw.(type) {
	case
		*tcpResponseWriter,
		*udpResponseWriter:
		s.disposer.Dispose(resp)
	default:
		// Go on.
	}
}

// serveDNSMsgInternal serves the DNS request and uses recorder as a
// [ResponseWriter].  This method is supposed to be called from serveDNSMsg, the
// recorded response is used for counting metrics.  logger, req, and rw must not
// be nil.
//
// TODO(a.garipov):  Think of a better name or refactor its connections to other
// methods.
func (s *ServerBase) serveDNSMsgInternal(
	ctx context.Context,
	logger *slog.Logger,
	req *dns.Msg,
	rw *RecorderResponseWriter,
) {
	var resp *dns.Msg

	// Check if we can accept this message.
	switch action, reason := s.acceptMsg(req); action {
	case dns.MsgReject:
		logger.DebugContext(ctx, "rejected", "reason", reason)
		resp = genErrorResponse(req, dns.RcodeFormatError)
	case dns.MsgRejectNotImplemented:
		logger.DebugContext(ctx, "not implemented", "reason", reason)
		resp = genErrorResponse(req, dns.RcodeNotImplemented)
	case dns.MsgIgnore:
		logger.DebugContext(ctx, "ignoring", "reason", reason)
		s.metrics.OnInvalidMsg(ctx)

		return
	}

	// If resp is not empty at this stage, the request is invalid and we should
	// simply exit here.
	if resp != nil {
		logger.DebugContext(ctx, "writing response", "rcode", resp.Rcode)
		err := rw.WriteMsg(ctx, req, resp)
		if err != nil {
			logger.DebugContext(ctx, "error writing reject response", slogutil.KeyError, err)
		}

		return
	}

	err := s.handler.ServeDNS(ctx, rw, req)
	if err != nil {
		logger.DebugContext(ctx, "handler error", slogutil.KeyError, err)
		s.metrics.OnError(ctx, err)

		resp = genErrorResponse(req, dns.RcodeServerFailure)
		if isNonCriticalNetError(err) {
			addEDE(req, resp, dns.ExtendedErrorCodeNetworkError, "")
		}

		err = rw.WriteMsg(ctx, req, resp)
		if err != nil {
			logger.DebugContext(ctx, "error writing handler response", slogutil.KeyError, err)
		}
	}
}

// addEDE adds an Extended DNS Error (EDE) option to the blocked response
// message, if the request indicates EDNS support.
func addEDE(req, resp *dns.Msg, code uint16, text string) {
	reqOpt := req.IsEdns0()
	if reqOpt == nil {
		// Requestor doesn't implement EDNS, see
		// https://datatracker.ietf.org/doc/html/rfc6891#section-7.
		return
	}

	respOpt := resp.IsEdns0()
	if respOpt == nil {
		resp.SetEdns0(reqOpt.UDPSize(), reqOpt.Do())
		respOpt = resp.Extra[len(resp.Extra)-1].(*dns.OPT)
	}

	respOpt.Option = append(respOpt.Option, &dns.EDNS0_EDE{
		InfoCode:  code,
		ExtraText: text,
	})
}

// acceptMsg checks if we should process the incoming DNS query.  msg must not be
// nil.
func (s *ServerBase) acceptMsg(msg *dns.Msg) (action dns.MsgAcceptAction, reason string) {
	if msg.Response {
		return dns.MsgIgnore, "message is a response"
	}

	if msg.Opcode != dns.OpcodeQuery && msg.Opcode != dns.OpcodeNotify {
		return dns.MsgRejectNotImplemented, fmt.Sprintf("unsupported opcode %d", msg.Opcode)
	}

	// There can only be one question in request, unless DNS Cookies are
	// involved.  See AGDNS-738.
	if len(msg.Question) != 1 {
		return dns.MsgReject, "bad number of questions"
	}

	// NOTIFY requests can have a SOA in the ANSWER section.  See RFC 1996
	// Section 3.7 and 3.11.
	if len(msg.Answer) > 1 {
		return dns.MsgReject, "bad number of answers"
	}

	// IXFR request could have one SOA RR in the NS section.  See RFC 1995,
	// section 3.
	if len(msg.Ns) > 1 {
		return dns.MsgReject, "bad number of ns records"
	}

	return dns.MsgAccept, ""
}

// handlePanicAndExit writes panic info to log, reports it to the registered
// [MetricsListener] and calls [os.Exit] with [osutil.ExitCodeFailure].
func (s *ServerBase) handlePanicAndExit(ctx context.Context) {
	v := recover()
	if v == nil {
		return
	}

	s.handlePanic(ctx, v)

	os.Exit(osutil.ExitCodeFailure)
}

// handlePanic is the common panic handler.  v should be the recovered value and
// must not be nil.
func (s *ServerBase) handlePanic(ctx context.Context, v any) {
	s.metrics.OnPanic(ctx, v)

	l, ok := slogutil.LoggerFromContext(ctx)
	if !ok {
		l = s.baseLogger
	}

	slogutil.PrintRecovered(ctx, l, v)
}

// handlePanicAndRecover writes panic info to log, reports it to the registered
// MetricsListener.
func (s *ServerBase) handlePanicAndRecover(ctx context.Context) {
	v := recover()
	if v == nil {
		return
	}

	s.handlePanic(ctx, v)
}

// listenUDP initializes and starts s.udpListener using s.addr.  If the TCP
// listener is already running, its address is used instead to properly handle
// the case when port 0 is used as both listeners should use the same port, and
// we only learn it after the first one was started.
func (s *ServerBase) listenUDP(ctx context.Context) (err error) {
	addr := s.addr
	if s.tcpListener != nil {
		addr = s.tcpListener.Addr().String()
	}

	conn, err := s.listenConfig.ListenPacket(ctx, "udp", addr)
	if err != nil {
		return err
	}

	s.udpListener = conn

	return nil
}

// listenTCP initializes and starts s.tcpListener using s.addr.  If the UDP
// listener is already running, its address is used instead to properly handle
// the case when port 0 is used as both listeners should use the same port, and
// we only learn it after the first one was started.
func (s *ServerBase) listenTCP(ctx context.Context) (err error) {
	addr := s.addr
	if s.udpListener != nil {
		addr = s.udpListener.LocalAddr().String()
	}

	l, err := s.listenConfig.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}

	s.tcpListener = l

	return nil
}

// closeListeners stops UDP and TCP listeners.
func (s *ServerBase) closeListeners(ctx context.Context) {
	if s.udpListener != nil {
		err := s.udpListener.Close()
		if err != nil {
			s.baseLogger.InfoContext(ctx, "closing udp listener", slogutil.KeyError, err)
		}
	}

	if s.tcpListener != nil {
		err := s.tcpListener.Close()
		if err != nil {
			s.baseLogger.InfoContext(ctx, "closing tcp listener", slogutil.KeyError, err)
		}
	}
}

// waitShutdown waits either until context deadline OR ServerBase.wg.
func (s *ServerBase) waitShutdown(ctx context.Context) (err error) {
	// Using this channel to wait until all goroutines finish their work
	closed := make(chan struct{})

	go func() {
		defer slogutil.RecoverAndLog(ctx, s.baseLogger)

		// Wait until all tasks exit.
		s.activeTaskWG.Wait()
		close(closed)
	}()

	select {
	case <-closed:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// isStarted returns true if the server is started.
func (s *ServerBase) isStarted() (started bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.started
}
