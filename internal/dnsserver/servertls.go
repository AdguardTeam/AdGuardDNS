package dnsserver

import (
	"context"
	"crypto/tls"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
)

// ConfigTLS is a struct that needs to be passed to NewServerTLS to
// initialize a new ServerTLS instance.
type ConfigTLS struct {
	ConfigDNS

	// TLSConfig is the TLS configuration for TLS.
	TLSConfig *tls.Config
}

// ServerTLS implements a DNS-over-TLS server.
// Note that it heavily relies on ServerDNS.
type ServerTLS struct {
	*ServerDNS

	conf ConfigTLS
}

// type check
var _ Server = (*ServerTLS)(nil)

// NewServerTLS creates a new ServerTLS instance.
func NewServerTLS(conf ConfigTLS) (s *ServerTLS) {
	srv := newServerDNS(ProtoDoT, conf.ConfigDNS)
	s = &ServerTLS{
		ServerDNS: srv,
		conf:      conf,
	}

	return s
}

// Start implements the dnsserver.Server interface for *ServerTLS.
func (s *ServerTLS) Start(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "starting dot server: %w") }()

	s.lock.Lock()
	defer s.lock.Unlock()

	if s.conf.TLSConfig == nil {
		return errors.Error("tls config is required")
	}

	if s.started {
		return ErrServerAlreadyStarted
	}

	log.Info("[%s]: Starting the server", s.name)

	ctx = ContextWithServerInfo(ctx, &ServerInfo{
		Name:  s.name,
		Addr:  s.addr,
		Proto: s.proto,
	})

	// Start listening to TCP on the specified addr
	err = s.listenTLS(ctx)
	if err != nil {
		return err
	}

	// Start the TLS server loop
	if s.tcpListener != nil {
		go s.startServeTCP(ctx)
	}

	// TODO(ameshkov): Consider only setting s.started to true once the
	// listeners are up.
	s.started = true

	log.Info("[%s]: Server has been started", s.Name())

	return nil
}

// Shutdown implements the dnsserver.Server interface for *ServerTLS.
func (s *ServerTLS) Shutdown(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "shutting down dot server: %w") }()

	return s.ServerDNS.Shutdown(ctx)
}

// startServeTCP starts the TCP listen loop and handles errors if any.
func (s *ServerTLS) startServeTCP(ctx context.Context) {
	// We do not recover from panics here since if this go routine panics
	// the application won't be able to continue listening to DoT
	defer s.handlePanicAndExit(ctx)

	log.Info("[%s]: Start listening to tls://%s", s.Name(), s.Addr())
	err := s.serveTCP(ctx, s.tcpListener)
	if err != nil {
		log.Info("[%s]: Finished listening to tls://%s due to %v", s.Name(), s.Addr(), err)
	}
}

// listenTLS creates the TLS listener for s.addr.
func (s *ServerTLS) listenTLS(ctx context.Context) (err error) {
	l, err := s.listenConfig.Listen(ctx, "tcp", s.addr)
	if err != nil {
		return err
	}

	s.tcpListener = newTLSListener(l, s.conf.TLSConfig)

	return nil
}
