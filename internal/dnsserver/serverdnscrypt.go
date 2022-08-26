package dnsserver

import (
	"context"
	"net"

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
		ServerBase: newServerBase(conf.ConfigBase),
		conf:       conf,
	}
}

// Start starts the server and starts processing queries.
func (s *ServerDNSCrypt) Start(ctx context.Context) (err error) {
	s.lock.Lock()
	defer s.lock.Unlock()

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

	switch s.proto {
	case ProtoDNSCryptUDP:
		err = s.listenUDP(ctx)
		if err != nil {
			return err
		}

		go s.startServeUDP(ctx)
	case ProtoDNSCryptTCP:
		err = s.listenTCP(ctx)
		if err != nil {
			return err
		}

		go s.startServeTCP(ctx)
	default:
		return ErrInvalidArgument
	}

	log.Info("[%s]: Server has been started", s.Name())

	return nil
}

// Shutdown closes active connections and listeners (if they're not closed already).
func (s *ServerDNSCrypt) Shutdown(ctx context.Context) (err error) {
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

	network := NetworkUDP
	if h.srv.proto == ProtoDNSCryptTCP {
		network = NetworkTCP
	}

	msg := nrw.Msg()
	normalize(network, r, msg)

	return rw.WriteMsg(msg)
}

// listenUDP creates the UDP listener for the ServerDNSCrypt.addr.
func (s *ServerDNSCrypt) listenUDP(ctx context.Context) (err error) {
	var l net.PacketConn
	l, err = listenUDP(ctx, s.addr)
	if err != nil {
		return err
	}

	u, ok := l.(*net.UDPConn)
	if !ok {
		return ErrInvalidArgument
	}

	if err = setUDPSocketOptions(u); err != nil {
		return err
	}

	s.udpListener = u

	return nil
}

// listenTCP creates the TCP listener for the ServerDNSCrypt.addr.
func (s *ServerDNSCrypt) listenTCP(ctx context.Context) (err error) {
	var l net.Listener
	l, err = listenTCP(ctx, s.addr)
	if err != nil {
		return err
	}

	s.tcpListener = l

	return nil
}
