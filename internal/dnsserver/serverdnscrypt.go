package dnsserver

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
)

// ConfigDNSCrypt is a struct that needs to be passed to NewServerDNSCrypt to
// initialize a new ServerDNSCrypt instance.
type ConfigDNSCrypt struct {
	ConfigBase

	// DNSCryptResolverCert is a DNSCrypt server certificate.
	DNSCryptResolverCert *dnscrypt.Cert

	// DNSCryptProviderName is a DNSCrypt provider name (see DNSCrypt spec).
	DNSCryptProviderName string
}

// ServerDNSCrypt is a DNSCrypt server implementation.
type ServerDNSCrypt struct {
	*ServerBase

	dnsCryptServer *dnscrypt.Server

	conf ConfigDNSCrypt
}

// type check
var _ Server = (*ServerDNSCrypt)(nil)

// NewServerDNSCrypt creates a new instance of ServerDNSCrypt.
func NewServerDNSCrypt(conf ConfigDNSCrypt) (s *ServerDNSCrypt) {
	if conf.ListenConfig == nil {
		conf.ListenConfig = netext.DefaultListenConfig(nil)
	}

	return &ServerDNSCrypt{
		ServerBase: newServerBase(ProtoDNSCrypt, conf.ConfigBase),
		conf:       conf,
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

	log.Info("[%s]: Starting the server", s.Name())

	ctx = ContextWithServerInfo(ctx, &ServerInfo{
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

	s.started = true

	log.Info("[%s]: Server has been started", s.Name())

	return nil
}

// Shutdown implements the dnsserver.Server interface for *ServerDNSCrypt.
func (s *ServerDNSCrypt) Shutdown(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "shutting down dnscrypt server: %w") }()

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
		s.closeListeners()

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

	log.Info("[%s]: Start listening to udp://%s", s.Name(), s.Addr())

	// TODO(ameshkov): Add context to the ServeTCP and ServeUDP methods in
	// dnscrypt/v3.  Or at least add ServeTCPContext and ServeUDPContext
	// methods for now.
	//
	// TODO(ameshkov): Redo the dnscrypt module to make it not depend on
	// *net.UDPConn and use net.PacketConn instead.
	err := s.dnsCryptServer.ServeUDP(s.udpListener.(*net.UDPConn))
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
	s.mu.Lock()
	defer s.mu.Unlock()

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
	ctx, cancel := h.srv.requestContext()
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
