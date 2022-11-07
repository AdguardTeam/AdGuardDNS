package dnsserver

import (
	"context"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
)

// ConfigDNSCrypt is a struct that needs to be passed to NewServerDNSCrypt to
// initialize a new ServerDNSCrypt instance.
type ConfigDNSCrypt struct {
	ConfigBase

	// DNSCryptProviderName is a DNSCrypt provider name (see DNSCrypt spec).
	DNSCryptProviderName string

	// DNSCryptResolverCert is a DNSCrypt server certificate.
	DNSCryptResolverCert *dnscrypt.Cert
}

// ServerDNSCrypt is a DNSCrypt server implementation.
type ServerDNSCrypt struct {
	*ServerBase

	conf ConfigDNSCrypt

	// Internal server properties
	// --

	dnsCryptServer *dnscrypt.Server // dnscrypt server instance
}

// type check
var _ Server = (*ServerDNSCrypt)(nil)

// NewServerDNSCrypt creates a new instance of ServerDNSCrypt.
func NewServerDNSCrypt(conf ConfigDNSCrypt) (s *ServerDNSCrypt) {
	return &ServerDNSCrypt{
		ServerBase: newServerBase(ProtoDNSCrypt, conf.ConfigBase),
		conf:       conf,
	}
}

// Start implements the dnsserver.Server interface for *ServerDNSCrypt.
func (s *ServerDNSCrypt) Start(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "starting dnscrypt server: %w", err) }()

	s.lock.Lock()
	defer s.lock.Unlock()

	// First, validate the protocol.
	if s.proto != ProtoDNSCrypt {
		return ErrInvalidArgument
	}

	if s.started {
		return ErrServerAlreadyStarted
	}
	s.started = true

	log.Info("[%s]: Starting the server", s.Name())

	ctx = ContextWithServerInfo(ctx, ServerInfo{
		Name:  s.name,
		Addr:  s.addr,
		Proto: s.proto,
	})

	// Create DNSCrypt server with a handler
	s.dnsCryptServer = &dnscrypt.Server{
		ProviderName: s.conf.DNSCryptProviderName,
		ResolverCert: s.conf.DNSCryptResolverCert,
		Handler: &dnsCryptHandler{
			srv: s,
		},
	}

	err = s.startServe(ctx)
	if err != nil {
		return err
	}

	log.Info("[%s]: Server has been started", s.Name())

	return nil
}

// Shutdown implements the dnsserver.Server interface for *ServerDNSCrypt.
func (s *ServerDNSCrypt) Shutdown(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "shutting down dnscrypt server: %w", err) }()

	log.Info("[%s]: Stopping the server", s.Name())
	err = s.shutdown()
	if err != nil {
		log.Info("[%s]: Failed to shutdown: %v", s.Name(), err)

		return err
	}

	err = s.dnsCryptServer.Shutdown(ctx)
	log.Info("[%s]: Finished stopping the server", s.Name())

	return err
}

// startServe creates listeners and starts serving DNSCrypt.
func (s *ServerDNSCrypt) startServe(ctx context.Context) (err error) {
	if s.network.CanUDP() {
		err = s.listenUDP(ctx)
		if err != nil {
			return err
		}

		go s.startServeUDP(ctx)
	}

	if s.network.CanTCP() {
		err = s.listenTCP(ctx)
		if err != nil {
			return err
		}

		go s.startServeTCP(ctx)
	}

	return nil
}

// startServeUDP starts the UDP listener loop.
func (s *ServerDNSCrypt) startServeUDP(ctx context.Context) {
	// We do not recover from panics here since if this go routine panics
	// the application won't be able to continue listening to DoT.
	defer s.handlePanicAndExit(ctx)

	log.Info("[%s]: Start listening to udp://%s", s.Name(), s.Addr())

	// TODO(ameshkov): Add context to the ServeTCP and ServeUDP methods in
	// dnscrypt/v3.  Or at least add ServeTCPContext and ServeUDPContext
	// methods for now.
	err := s.dnsCryptServer.ServeUDP(s.udpListener)
	if err != nil {
		log.Info("[%s]: Finished listening to udp://%s due to %v", s.Name(), s.Addr(), err)
	}
}

// startServeTCP starts the TCP listener loop.
func (s *ServerDNSCrypt) startServeTCP(ctx context.Context) {
	// We do not recover from panics here since if this go routine panics
	// the application won't be able to continue listening to DoT.
	defer s.handlePanicAndExit(ctx)

	log.Info("[%s]: Start listening to tcp://%s", s.Name(), s.Addr())

	// TODO(ameshkov): Add context to the ServeTCP and ServeUDP methods in
	// dnscrypt/v3.  Or at least add ServeTCPContext and ServeUDPContext
	// methods for now.
	err := s.dnsCryptServer.ServeTCP(s.tcpListener)
	if err != nil {
		log.Info("[%s]: Finished listening to tcp://%s due to %v", s.Name(), s.Addr(), err)
	}
}

// shutdown marks the server as stopped and closes active listeners.
func (s *ServerDNSCrypt) shutdown() (err error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if !s.started {
		return ErrServerNotStarted
	}

	// First, mark it as stopped
	s.started = false

	// Now close all listeners
	s.closeListeners()

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
	ctx := h.srv.requestContext()
	ctx = ContextWithClientInfo(ctx, ClientInfo{})

	nrw := NewNonWriterResponseWriter(rw.LocalAddr(), rw.RemoteAddr())
	written := h.srv.serveDNSMsg(ctx, r, nrw)
	if !written {
		// If there was no response from the handler, return SERVFAIL.
		return rw.WriteMsg(genErrorResponse(r, dns.RcodeServerFailure))
	}

	network := NetworkFromAddr(rw.LocalAddr())
	msg := nrw.Msg()
	normalize(network, r, msg)

	return rw.WriteMsg(msg)
}
