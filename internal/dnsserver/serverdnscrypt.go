package dnsserver

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
)

// ConfigDNSCrypt is a struct that needs to be passed to NewServerDNSCrypt to
// initialize a new ServerDNSCrypt instance.
type ConfigDNSCrypt struct {
	// Base is the base configuration for this server.  It must not be nil
	// and must be valid.
	Base *ConfigBase

	// ResolverCert is a DNSCrypt server certificate.  It must not be nil.
	ResolverCert *dnscrypt.Cert

	// ProviderName is a DNSCrypt provider name, see DNSCrypt spec.  It must not
	// be empty.
	ProviderName string
}

// ServerDNSCrypt is a DNSCrypt server implementation.
//
// TODO(a.garipov):  Consider unembedding ServerBase.
type ServerDNSCrypt struct {
	*ServerBase

	server       *dnscrypt.Server
	resolverCert *dnscrypt.Cert
	providerName string
}

// type check
var _ Server = (*ServerDNSCrypt)(nil)

// NewServerDNSCrypt creates a new instance of ServerDNSCrypt.  c must not be
// nil and must be valid.
func NewServerDNSCrypt(c *ConfigDNSCrypt) (s *ServerDNSCrypt) {
	c.Base.ListenConfig = cmp.Or(c.Base.ListenConfig, netext.DefaultListenConfig(nil))

	return &ServerDNSCrypt{
		ServerBase:   newServerBase(ProtoDNSCrypt, c.Base),
		resolverCert: c.ResolverCert,
		providerName: c.ProviderName,
	}
}

// Start implements the dnsserver.Server interface for *ServerDNSCrypt.
func (s *ServerDNSCrypt) Start(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "starting dnscrypt server: %w") }()

	s.mu.Lock()
	defer s.mu.Unlock()

	// First, validate the protocol.
	if s.proto != ProtoDNSCrypt {
		return ErrInvalidArgument
	}

	if s.started {
		return ErrServerAlreadyStarted
	}

	s.baseLogger.InfoContext(ctx, "starting server")

	ctx = ContextWithServerInfo(ctx, &ServerInfo{
		Name:  s.name,
		Addr:  s.addr,
		Proto: s.proto,
	})

	// Create DNSCrypt server with a handler
	s.server = &dnscrypt.Server{
		ProviderName: s.providerName,
		ResolverCert: s.resolverCert,
		Handler: &dnsCryptHandler{
			srv: s,
		},
	}

	err = s.startServe(ctx)
	if err != nil {
		return err
	}

	s.started = true

	s.baseLogger.InfoContext(ctx, "server has been started")

	return nil
}

// Shutdown implements the dnsserver.Server interface for *ServerDNSCrypt.
func (s *ServerDNSCrypt) Shutdown(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "shutting down dnscrypt server: %w") }()

	s.baseLogger.InfoContext(ctx, "shutting down server")

	err = s.shutdown(ctx)
	if err != nil {
		s.baseLogger.WarnContext(ctx, "error while shutting down", slogutil.KeyError, err)

		return err
	}

	err = s.server.Shutdown(ctx)

	s.baseLogger.InfoContext(ctx, "server has been shut down")

	return err
}

// startServe creates listeners and starts serving DNSCrypt.
func (s *ServerDNSCrypt) startServe(ctx context.Context) (err error) {
	var errs []error

	if s.network.CanUDP() {
		err = s.listenUDP(ctx)
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			errs = append(errs, err)
		}
	}

	if s.network.CanTCP() {
		err = s.listenTCP(ctx)
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		s.closeListeners(ctx)

		return fmt.Errorf("creating listeners: %w", errors.Join(errs...))
	}

	go s.startServeUDP(ctx)
	go s.startServeTCP(ctx)

	return nil
}

// startServeUDP starts the UDP listener loop.
func (s *ServerDNSCrypt) startServeUDP(ctx context.Context) {
	// We do not recover from panics here since if this go routine panics
	// the application won't be able to continue listening to DoT.
	defer s.handlePanicAndExit(ctx)

	s.baseLogger.InfoContext(ctx, "starting listening udp")

	// TODO(ameshkov): Add context to the ServeTCP and ServeUDP methods in
	// dnscrypt/v3.  Or at least add ServeTCPContext and ServeUDPContext
	// methods for now.
	//
	// TODO(ameshkov): Redo the dnscrypt module to make it not depend on
	// *net.UDPConn and use net.PacketConn instead.
	err := s.server.ServeUDP(s.udpListener.(*net.UDPConn))
	if err != nil {
		s.baseLogger.WarnContext(ctx, "listening udp failed", slogutil.KeyError, err)
	}
}

// startServeTCP starts the TCP listener loop.
func (s *ServerDNSCrypt) startServeTCP(ctx context.Context) {
	// We do not recover from panics here since if this go routine panics
	// the application won't be able to continue listening to DoT.
	defer s.handlePanicAndExit(ctx)

	s.baseLogger.InfoContext(ctx, "starting listening tcp")

	// TODO(ameshkov): Add context to the ServeTCP and ServeUDP methods in
	// dnscrypt/v3.  Or at least add ServeTCPContext and ServeUDPContext
	// methods for now.
	err := s.server.ServeTCP(s.tcpListener)
	if err != nil {
		s.baseLogger.WarnContext(ctx, "listening tcp failed", slogutil.KeyError, err)
	}
}

// shutdown marks the server as stopped and closes active listeners.
func (s *ServerDNSCrypt) shutdown(ctx context.Context) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		return ErrServerNotStarted
	}

	// First, mark it as stopped
	s.started = false

	// Now close all listeners
	s.closeListeners(ctx)

	return nil
}

// dnsCryptHandler is a dnscrypt.Handler implementation.
type dnsCryptHandler struct {
	srv *ServerDNSCrypt
}

// compile-time type check
var _ dnscrypt.Handler = (*dnsCryptHandler)(nil)

// ServeDNS processes the DNS query, implements dnscrypt.Handler.
func (h *dnsCryptHandler) ServeDNS(rw dnscrypt.ResponseWriter, r *dns.Msg) (err error) {
	defer func() { err = errors.Annotate(err, "dnscrypt: %w") }()

	// TODO(ameshkov): Use the context from the arguments once it's added there.
	ctx, cancel := h.srv.requestContext(context.Background())
	defer cancel()

	ctx = ContextWithRequestInfo(ctx, &RequestInfo{StartTime: time.Now()})

	nrw := NewNonWriterResponseWriter(rw.LocalAddr(), rw.RemoteAddr())
	written := h.srv.serveDNSMsg(ctx, r, nrw)
	if !written {
		// If there was no response from the handler, return SERVFAIL.
		return rw.WriteMsg(genErrorResponse(r, dns.RcodeServerFailure))
	}

	network := NetworkFromAddr(rw.LocalAddr())
	msg := nrw.Msg()
	normalize(network, ProtoDNSCrypt, r, msg, dns.MaxMsgSize)

	return rw.WriteMsg(msg)
}
