package dnsserver

import (
	"context"
	"net"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// ConfigBase contains the necessary minimum that every Server needs to
// be initialized.
type ConfigBase struct {
	// Name is used for logging, and it may be used for perf counters reporting.
	Name string

	// Addr is the address the server listens to.  See go doc net.Dial for
	// the documentation on the address format.
	Addr string

	// Network is the network this server listens to.  If empty, the server will
	// listen to all networks that are supposed to be used by the server's
	// protocol.  Note, that it only makes sense for [ServerDNS],
	// [ServerDNSCrypt], and [ServerHTTPS].
	Network Network

	// Handler is a handler that processes incoming DNS messages.
	// If not set, we'll use the default handler that returns error response
	// to any query.
	Handler Handler

	// Metrics is the object we use for collecting performance metrics.
	// This field is optional.
	Metrics MetricsListener

	// BaseContext is a function that should return the base context. If not
	// set, we'll be using context.Background().
	BaseContext func() (ctx context.Context)

	// ListenConfig, when set, is used to set options of connections used by the
	// DNS server.  If nil, an appropriate default ListenConfig is used.
	ListenConfig netext.ListenConfig
}

// ServerBase implements base methods that every Server implementation uses.
type ServerBase struct {
	// name is used for logging and it may be used for perf counters reporting.
	name string

	// addr is the address the server listens to.
	addr string

	// proto is the server protocol.
	proto Protocol

	// network is the network to listen to.  It only makes sense for the
	// following protocols: ProtoDNS, ProtoDNSCrypt, ProtoDoH.
	network Network

	// handler is a handler that processes incoming DNS messages.
	handler Handler

	// baseContext is a function that should return the base context.
	baseContext func() (ctx context.Context)

	// metrics is the object we use for collecting performance metrics.
	metrics MetricsListener

	// listenConfig is used to set tcpListener and udpListener.
	listenConfig netext.ListenConfig

	// Server operation
	// --

	// tcpListener is used to accept new TCP connections.  It is nil for servers
	// that don't use TCP.
	tcpListener net.Listener

	// udpListener is used to accept new UDP messages.  It is nil for servers
	// that don't use UDP.
	udpListener net.PacketConn

	// Shutdown handling
	// --

	// lock protects started, tcpListener and udpListener.
	lock    sync.RWMutex
	started bool
	// wg tracks active workers (listeners or query processing). Shutdown
	// won't finish until there's at least one active worker.
	wg sync.WaitGroup
}

// type check
var _ Server = (*ServerBase)(nil)

// newServerBase creates a new instance of ServerBase and initializes
// some of its internal properties.
func newServerBase(proto Protocol, conf ConfigBase) (s *ServerBase) {
	s = &ServerBase{
		name:         conf.Name,
		addr:         conf.Addr,
		proto:        proto,
		network:      conf.Network,
		handler:      conf.Handler,
		metrics:      conf.Metrics,
		listenConfig: conf.ListenConfig,
		baseContext:  conf.BaseContext,
	}

	if s.baseContext == nil {
		s.baseContext = context.Background
	}

	if s.metrics == nil {
		s.metrics = &EmptyMetricsListener{}
	}

	if s.handler == nil {
		s.handler = notImplementedHandlerFunc
	}

	return s
}

// Name implements the [dnsserver.Server] interface for *ServerBase.
func (s *ServerBase) Name() (name string) {
	return s.name
}

// Proto implements the [dnsserver.Server] interface for *ServerBase.
func (s *ServerBase) Proto() (proto Protocol) {
	return s.proto
}

// Network implements the [dnsserver.Server] interface for *ServerBase.
func (s *ServerBase) Network() (network Network) {
	return s.network
}

// Addr implements the [dnsserver.Server] interface for *ServerBase.
func (s *ServerBase) Addr() (addr string) {
	return s.addr
}

// Start implements the [dnsserver.Server] interface for *ServerBase.
func (s *ServerBase) Start(_ context.Context) (err error) {
	panic("*ServerBase must not be used directly")
}

// Shutdown implements the [dnsserver.Server] interface for *ServerBase.
func (s *ServerBase) Shutdown(_ context.Context) (err error) {
	panic("*ServerBase must not be used directly")
}

// LocalTCPAddr implements the [dnsserver.Server] interface for *ServerBase.
func (s *ServerBase) LocalTCPAddr() (addr net.Addr) {
	if s.tcpListener != nil {
		return s.tcpListener.Addr()
	}

	return nil
}

// LocalUDPAddr implements the [dnsserver.Server] interface for *ServerBase.
func (s *ServerBase) LocalUDPAddr() (addr net.Addr) {
	if s.udpListener != nil {
		return s.udpListener.LocalAddr()
	}

	return nil
}

// requestContext returns a context for one request.  It adds the start time and
// the server information.
func (s *ServerBase) requestContext() (ctx context.Context) {
	ctx = s.baseContext()
	ctx = ContextWithServerInfo(ctx, ServerInfo{
		Name:  s.name,
		Addr:  s.addr,
		Proto: s.proto,
	})
	ctx = ContextWithStartTime(ctx, time.Now())

	return ctx
}

// serveDNS processes the incoming DNS query and writes the response to the
// specified ResponseWriter.  written is false if no response was written.
func (s *ServerBase) serveDNS(ctx context.Context, m []byte, rw ResponseWriter) (written bool) {
	req := new(dns.Msg)
	if err := req.Unpack(m); err != nil {
		// Ignore the incoming message and let the connection hang as
		// it may be used to amplify
		s.metrics.OnInvalidMsg(ctx)

		return false
	}

	return s.serveDNSMsg(ctx, req, rw)
}

// serveDNSMsg processes the incoming DNS query and writes the response to the
// specified ResponseWriter.  written is false if no response was written.
func (s *ServerBase) serveDNSMsg(
	ctx context.Context,
	req *dns.Msg,
	rw ResponseWriter,
) (written bool) {
	hostname, qType := questionData(req)
	log.Debug("[%d] processing \"%s %s\"", req.Id, qType, hostname)

	recW := NewRecorderResponseWriter(rw)
	s.serveDNSMsgInternal(ctx, req, recW)

	ri := RequestInfo{RequestSize: req.Len()}
	resp := recW.Resp
	written = resp != nil
	if written {
		ri.ResponseSize = resp.Len()
	}

	ctx = ContextWithRequestInfo(ctx, ri)
	s.metrics.OnRequest(ctx, req, resp, rw)

	log.Debug("[%d]: finished processing \"%s %s\"", req.Id, qType, hostname)

	return written
}

// serveDNSMsgInternal serves the DNS request and uses recorder as a
// ResponseWriter. This method is supposed to be called from serveDNSMsg,
// the recorded response is used for counting metrics.
func (s *ServerBase) serveDNSMsgInternal(
	ctx context.Context,
	req *dns.Msg,
	rw *RecorderResponseWriter,
) {
	var resp *dns.Msg

	// Check if we can accept this message
	switch action := s.acceptMsg(req); action {
	case dns.MsgReject:
		log.Debug("[%d] Query format is invalid", req.Id)
		resp = genErrorResponse(req, dns.RcodeFormatError)
	case dns.MsgRejectNotImplemented:
		log.Debug("[%d] Rejecting this query", req.Id)
		resp = genErrorResponse(req, dns.RcodeNotImplemented)
	case dns.MsgIgnore:
		log.Debug("[%d] Ignoring this query", req.Id)
		s.metrics.OnInvalidMsg(ctx)

		return
	}

	// If resp is not empty at this stage, the request is invalid and we should
	// simply exit here.
	if resp != nil {
		// Ignore errors and just write the message
		log.Debug("[%d]: writing DNS response code %d", req.Id, resp.Rcode)
		err := rw.WriteMsg(ctx, req, resp)
		if err != nil {
			log.Debug("[%d]: error writing a response: %v", req.Id, err)
		}

		return
	}

	err := s.handler.ServeDNS(ctx, rw, req)
	if err != nil {
		log.Debug("[%d]: handler returned an error: %v", req.Id, err)
		s.metrics.OnError(ctx, err)
		resp = genErrorResponse(req, dns.RcodeServerFailure)
		err = rw.WriteMsg(ctx, req, resp)
		if err != nil {
			log.Debug("[%d]: error writing a response: %v", req.Id, err)
		}
	}
}

// acceptMsg checks if we should process the incoming DNS query.
func (s *ServerBase) acceptMsg(m *dns.Msg) (action dns.MsgAcceptAction) {
	if m.Response {
		log.Debug("[%d]: message rejected since this is a response", m.Id)

		return dns.MsgIgnore
	}

	if m.Opcode != dns.OpcodeQuery && m.Opcode != dns.OpcodeNotify {
		log.Debug("[%d]: rejected due to unsupported opcode", m.Opcode)

		return dns.MsgRejectNotImplemented
	}

	// There can only be one question in request, unless DNS Cookies are
	// involved.  See AGDNS-738.
	if len(m.Question) != 1 {
		log.Debug("[%d]: message rejected due to wrong number of questions", m.Id)

		return dns.MsgReject
	}

	// NOTIFY requests can have a SOA in the ANSWER section. See RFC 1996 Section 3.7 and 3.11.
	if len(m.Answer) > 1 {
		log.Debug("[%d]: message rejected due to wrong number of answers", m.Id)

		return dns.MsgReject
	}

	// IXFR request could have one SOA RR in the NS section. See RFC 1995, section 3.
	if len(m.Ns) > 1 {
		log.Debug("[%d]: message rejected due to wrong number of NS records", m.Id)

		return dns.MsgReject
	}

	return dns.MsgAccept
}

// handlePanicAndExit writes panic info to log, reports it to the registered
// MetricsListener and calls os.Exit with a positive exit code.
func (s *ServerBase) handlePanicAndExit(ctx context.Context) {
	if v := recover(); v != nil {
		log.Error(
			"%q(%s://%s): panic encountered, exiting: %v\n%s",
			s.name,
			s.proto,
			s.addr,
			v,
			string(debug.Stack()),
		)

		s.metrics.OnPanic(ctx, v)

		os.Exit(1)
	}
}

// handlePanicAndRecover writes panic info to log, reports it to the registered
// MetricsListener.
func (s *ServerBase) handlePanicAndRecover(ctx context.Context) {
	if v := recover(); v != nil {
		log.Error(
			"%s %s://%s: panic encountered, recovered: %s\n%s",
			s.name,
			s.addr,
			s.proto,
			v,
			string(debug.Stack()),
		)
		s.metrics.OnPanic(ctx, v)
	}
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
func (s *ServerBase) closeListeners() {
	if s.udpListener != nil {
		err := s.udpListener.Close()
		if err != nil {
			log.Info("[%s]: Failed to close NetworkUDP listener: %v", s.Name(), err)
		}
	}
	if s.tcpListener != nil {
		err := s.tcpListener.Close()
		if err != nil {
			log.Info("[%s]: Failed to close NetworkTCP listener: %v", s.Name(), err)
		}
	}
}

// waitShutdown waits either until context deadline OR ServerBase.wg.
func (s *ServerBase) waitShutdown(ctx context.Context) (err error) {
	// Using this channel to wait until all goroutines finish their work
	closed := make(chan struct{})
	go func() {
		defer log.OnPanic("waitShutdown")

		// wait until all queries are processed
		s.wg.Wait()
		close(closed)
	}()

	var ctxErr error
	select {
	case <-closed:
		// Do nothing here
	case <-ctx.Done():
		ctxErr = ctx.Err()
	}

	return ctxErr
}

// isStarted returns true if the server is started.
func (s *ServerBase) isStarted() (started bool) {
	s.lock.RLock()
	started = s.started
	s.lock.RUnlock()
	return started
}
