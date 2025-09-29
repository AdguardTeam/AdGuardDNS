package dnsserver

import (
	"context"
	"crypto/tls"

	"github.com/AdguardTeam/golibs/errors"
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
		go s.serveTCP(ctx, s.tcpListener, "tls")
	}

	// TODO(ameshkov):  Consider only setting s.started to true once the
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

// listenTLS creates the TLS listener for s.addr.
func (s *ServerTLS) listenTLS(ctx context.Context) (err error) {
	l, err := s.listenConfig.Listen(ctx, "tcp", s.addr)
	if err != nil {
		return err
	}

	s.tcpListener = newTLSListener(l, s.tlsConf)

	return nil
}
