package dnsserver

import (
	"context"
	"net"
	"os"
	"runtime/debug"
	"sync"
	"time"

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
	// Proto is the server protocol.
	Proto Protocol
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
}

// ServerBase implements base methods that every Server implementation uses.
type ServerBase struct {
	// name is used for logging and it may be used for perf counters reporting.
	name string
	// addr is the address the server listens to.
	addr string
	// proto is the server protocol.
	proto Protocol
	// handler is a handler that processes incoming DNS messages.
	handler Handler
	// baseContext is a function that should return the base context.
	baseContext func() (ctx context.Context)
	// metrics is the object we use for collecting performance metrics.
	metrics MetricsListener

	// Server operation
	// --

	// will be nil for servers that don't use TCP.
	tcpListener net.Listener
	// will be nil for servers that don't use UDP.
	udpListener *net.UDPConn

	// Shutdown handling
	// --

	// lock protects started, tcpListener and udpListener.
	lock    sync.RWMutex
	started bool
	// wg tracks active workers (listeners or query processing). Shutdown
	// won't finish until there's at least one active worker.
	wg sync.WaitGroup
}

// newServerBase creates a new instance of ServerBase and initializes
// some of its internal properties.
func newServerBase(conf ConfigBase) (s *ServerBase) {
	s = &ServerBase{
		name:        conf.Name,
		addr:        conf.Addr,
		proto:       conf.Proto,
		handler:     conf.Handler,
		metrics:     conf.Metrics,
		baseContext: conf.BaseContext,
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

// Name returns the server name.  It is safe for concurrent use.
func (s *ServerBase) Name() (name string) {
	return s.name
}

// Addr returns the address the server was configured to listen to.  It is safe
// for concurrent use.
func (s *ServerBase) Addr() (addr string) {
	return s.addr
}

// LocalAddr returns the address the server listens to at the moment.
func (s *ServerBase) LocalAddr() (addr net.Addr) {
	if s.udpListener != nil {
		return s.udpListener.LocalAddr()
	}
	if s.tcpListener != nil {
		return s.tcpListener.Addr()
	}

	return nil
}

// Proto returns the protocol of the server.  It is safe for concurrent use.
func (s *ServerBase) Proto() (proto Protocol) {
	return s.proto
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

	ctx = ContextWithRequestSize(ctx, req.Len())
	recW := NewRecorderResponseWriter(rw)
	s.serveDNSMsgInternal(ctx, req, recW)

	resp := recW.Resp
	written = resp != nil
	if written {
		ctx = ContextWithResponseSize(ctx, resp.Len())
	}

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
