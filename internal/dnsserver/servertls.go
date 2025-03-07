package dnsserver

import (
	"context"
	"crypto/tls"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// ConfigTLS is a struct that needs to be passed to NewServerTLS to
// initialize a new ServerTLS instance.
type ConfigTLS struct {
	// TLSConfig is the TLS configuration for TLS.  It must not be nil.
	TLSConfig *tls.Config

	// DNS is the configuration for the underlying DNS server.  It must not be
	// nil and must be valid.
	DNS *ConfigDNS
}

// ServerTLS implements a DNS-over-TLS server.  Note that it heavily relies on
// ServerDNS.
//
// TODO(a.garipov):  Consider unembedding ServerDNS.
type ServerTLS struct {
	*ServerDNS

	tlsConf *tls.Config
}

// type check
var _ Server = (*ServerTLS)(nil)

// NewServerTLS creates a new ServerTLS instance.  c must not be nil and must be
// valid.
func NewServerTLS(c *ConfigTLS) (s *ServerTLS) {
	srv := newServerDNS(ProtoDoT, c.DNS)
	s = &ServerTLS{
		ServerDNS: srv,
		tlsConf:   c.TLSConfig,
	}

	return s
}

// Start implements the dnsserver.Server interface for *ServerTLS.
func (s *ServerTLS) Start(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "starting dot server: %w") }()

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

	s.baseLogger.InfoContext(ctx, "server has been started")

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

	s.baseLogger.InfoContext(ctx, "starting listening tls")

	err := s.serveTCP(ctx, s.tcpListener)
	if err != nil {
		s.baseLogger.WarnContext(ctx, "listening tls failed", slogutil.KeyError, err)
	}
}

// listenTLS creates the TLS listener for s.addr.
func (s *ServerTLS) listenTLS(ctx context.Context) (err error) {
	l, err := s.listenConfig.Listen(ctx, "tcp", s.addr)
	if err != nil {
		return err
	}

	s.tcpListener = newTLSListener(l, s.tlsConf)

	return nil
}
