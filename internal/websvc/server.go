package websvc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/optslog"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
)

// server contains an *http.Server as well as entities and data associated with
// it.
//
// TODO(a.garipov):  Join with similar structs in other projects and move to
// golibs/netutil/httputil.
//
// TODO(a.garipov):  Once the above standardization is complete, consider
// merging debugsvc and websvc into a single httpsvc.
type server struct {
	// mu protects http, logger, listener, and url.
	mu           *sync.Mutex
	http         *http.Server
	logger       *slog.Logger
	listener     net.Listener
	url          *url.URL
	listenConfig netext.ListenConfig

	initialAddr netip.AddrPort
}

// loggerKeyServer is the key used by [server] to identify itself.
const loggerKeyServer = "server"

// serverConfig is the configuration of a server.
type serverConfig struct {
	// BaseLogger is used to create the initial logger for the server.  It must
	// not be nil.
	BaseLogger *slog.Logger

	// TLSConf is the optional TLS configuration.
	TLSConf *tls.Config

	// ListenConfig is used for setting options for TCP connections.  It must
	// not be nil.
	ListenConfig netext.ListenConfig

	// BaseContext is an optional function that that returns the base context
	// for incoming requests on this server.  See [http.Server.BaseContext].
	BaseContext func(l net.Listener) (ctx context.Context)

	// Handler is the HTTP handler for this server.  It must not be nil.
	Handler http.Handler

	// InitialAddress is the initial address for the server.  It may have a zero
	// port, in which case the real port will be set in [server.serve].  It must
	// be set.
	InitialAddress netip.AddrPort

	// Timeout is the optional timeout for all operations.
	//
	// TODO(a.garipov):  Consider more fine-grained timeouts.
	Timeout time.Duration
}

// newServer returns a *server that is ready to serve HTTP queries.  The TCP
// listener is not started.  c must not be nil and must be valid.
func newServer(c *serverConfig) (s *server) {
	u := &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   c.InitialAddress.String(),
	}

	if c.TLSConf != nil {
		u.Scheme = urlutil.SchemeHTTPS
	}

	logger := c.BaseLogger.With(loggerKeyServer, u)

	s = &server{
		mu: &sync.Mutex{},
		http: &http.Server{
			Handler:           c.Handler,
			TLSConfig:         c.TLSConf,
			ReadTimeout:       c.Timeout,
			ReadHeaderTimeout: c.Timeout,
			WriteTimeout:      c.Timeout,
			IdleTimeout:       c.Timeout,
			ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
			BaseContext:       c.BaseContext,
		},
		logger:       logger,
		url:          u,
		listenConfig: c.ListenConfig,

		initialAddr: c.InitialAddress,
	}

	s.http.ConnContext = s.connContext

	return s
}

// connContext modifies the context for a new server connection.  It is intended
// to be used as a [http.Server.ConnContext].
func (s *server) connContext(parent context.Context, c net.Conn) (ctx context.Context) {
	laddr := netutil.NetAddrToAddrPort(c.LocalAddr())
	optslog.Trace1(parent, s.logger, "put local address in context", "laddr", laddr)

	return agd.ContextWithLocalAddress(parent, laddr.Addr())
}

// localAddr returns the local address of the server if the server has started
// listening; otherwise, it returns nil.
func (s *server) localAddr() (addr net.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if l := s.listener; l != nil {
		return l.Addr()
	}

	return nil
}

// serve starts s.  baseLogger is used as a base logger for s.  If s fails to
// serve with anything other than [http.ErrServerClosed], it causes an unhandled
// panic.  It is intended to be used as a goroutine.
//
// TODO(a.garipov):  Improve error handling.
func (s *server) serve(ctx context.Context, baseLogger *slog.Logger) {
	defer slogutil.RecoverAndLog(ctx, s.logger)

	tcpListener, err := s.listenConfig.Listen(ctx, "tcp", s.initialAddr.String())
	if err != nil {
		s.logger.ErrorContext(ctx, "listening tcp", slogutil.KeyError, err)

		panic(fmt.Errorf("websvc: listening tcp: %w", err))
	}

	var listener net.Listener
	if s.http.TLSConfig == nil {
		listener = tcpListener
	} else {
		listener = tls.NewListener(tcpListener, s.http.TLSConfig)
	}

	func() {
		s.mu.Lock()
		defer s.mu.Unlock()

		s.listener = listener

		// Reassign the address in case the port was zero.
		s.url.Host = listener.Addr().String()
		s.logger = baseLogger.With(loggerKeyServer, s.url)
		s.http.ErrorLog = slog.NewLogLogger(s.logger.Handler(), slog.LevelDebug)
	}()

	s.logger.InfoContext(ctx, "starting")
	err = s.http.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.logger.ErrorContext(ctx, "serving", slogutil.KeyError, err)

		panic(fmt.Errorf("websvc: serving: %w", err))
	}
}

// shutdown shuts s down.
func (s *server) shutdown(ctx context.Context) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error
	err = s.http.Shutdown(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("shutting down server %s: %w", s.url, err))
	}

	// Close the listener separately, as it might not have been closed if the
	// context has been canceled.
	//
	// NOTE:  The listener could remain uninitialized if
	// [netext.ListenConfig.Listen] failed in [s.serve].
	if l := s.listener; l != nil {
		err = l.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, fmt.Errorf("closing listener for server %s: %w", s.url, err))
		}
	}

	return errors.Join(errs...)
}
