package dnsserver

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

const (
	// DefaultReadTimeout is the default ServerDNS.ReadTimeout.
	DefaultReadTimeout = 2 * time.Second

	// DefaultWriteTimeout is the default ServerDNS.WriteTimeout.
	DefaultWriteTimeout = 2 * time.Second

	// DefaultTCPIdleTimeout is the default ServerDNS.TCPIdleTimeout.
	//
	// RFC5966:
	// "It is therefore RECOMMENDED that the default application-level idle
	// period should be of the order of seconds, but no particular value is
	// specified"
	DefaultTCPIdleTimeout = 30 * time.Second

	// MaxTCPIdleTimeout is the maximum TCP idle timeout per RFC 7828.
	MaxTCPIdleTimeout = math.MaxUint16 * 100 * time.Millisecond
)

// ConfigDNS is a struct that needs to be passed to NewServerDNS to
// initialize a new ServerDNS instance.
type ConfigDNS struct {
	// Base is the base configuration for this server.  It must not be nil and
	// must be valid.
	Base *ConfigBase

	// ReadTimeout is the net.Conn.SetReadTimeout value for new connections.
	// If not set it defaults to [DefaultReadTimeout].
	ReadTimeout time.Duration

	// WriteTimeout is the net.Conn.SetWriteTimeout value for connections.  If
	// not set it defaults to [DefaultWriteTimeout].
	WriteTimeout time.Duration

	// TCPIdleTimeout is the timeout for waiting between multiple queries.  If
	// not set it defaults to [DefaultTCPIdleTimeout].  It must not be greater
	// than [MaxTCPIdleTimeout].
	TCPIdleTimeout time.Duration

	// MaxPipelineCount is the maximum number of simultaneously processing TCP
	// messages per one connection.  If MaxPipelineEnabled is true, it must be
	// greater than zero.
	MaxPipelineCount uint

	// UDPSize is the size of the buffers used to read incoming UDP messages.
	// If not set it defaults to [dns.MinMsgSize], 512 B.
	UDPSize int

	// TCPSize is the initial size of the buffers used to read incoming TCP
	// messages.  If not set it defaults to [dns.MinMsgSize], 512 B.
	TCPSize int

	// MaxUDPRespSize is the maximum size of DNS response over UDP protocol.
	// If not set, [dns.MinMsgSize] is used.
	MaxUDPRespSize uint16

	// MaxPipelineEnabled, if true, enables TCP pipeline limiting.
	MaxPipelineEnabled bool
}

// ServerDNS is a plain DNS server (e.g. it supports UDP and TCP protocols).
//
// TODO(a.garipov):  Consider unembedding ServerBase.
type ServerDNS struct {
	*ServerBase

	// taskPool is a goroutine pool used to process DNS queries.  It is used to
	// prevent excessive growth of goroutine stacks.
	taskPool *taskPool

	// udpPool is a pool for UDP request buffers.
	udpPool *syncutil.Pool[[]byte]

	// tcpPool is a pool for TCP request buffers.
	tcpPool *syncutil.Pool[[]byte]

	// respPool is a pool for response buffers.
	respPool *syncutil.Pool[[]byte]

	// tcpConns is a set that is used to track active connections.
	tcpConns   *container.MapSet[net.Conn]
	tcpConnsMu *sync.Mutex

	readTimeout    time.Duration
	tcpIdleTimeout time.Duration
	writeTimeout   time.Duration

	maxPipelineCount uint

	maxUDPRespSize uint16

	maxPipelineEnabled bool
}

// type check
var _ Server = (*ServerDNS)(nil)

// NewServerDNS creates a new ServerDNS instance.  c must not be nil and must be
// valid.
func NewServerDNS(c *ConfigDNS) (s *ServerDNS) {
	return newServerDNS(ProtoDNS, c)
}

// newServerDNS initializes a new ServerDNS instance with the specified proto.
// This function is reused in [ServerTLS] as it is basically a plain
// DNS-over-TCP server with a TLS layer on top of it.  c must not be nil and
// must be valid.
func newServerDNS(proto Protocol, c *ConfigDNS) (s *ServerDNS) {
	// Init default settings first.
	c.ReadTimeout = cmp.Or(c.ReadTimeout, DefaultReadTimeout)
	c.WriteTimeout = cmp.Or(c.WriteTimeout, DefaultWriteTimeout)
	c.TCPIdleTimeout = cmp.Or(c.TCPIdleTimeout, DefaultTCPIdleTimeout)

	// TODO(a.garipov):  Return an error instead.
	if t := c.TCPIdleTimeout; t < 0 || t > MaxTCPIdleTimeout {
		panic(fmt.Errorf(
			"newServerDNS: tcp idle timeout: %w: must be >= 0 and <= %s, got %s",
			errors.ErrOutOfRange,
			MaxTCPIdleTimeout,
			t,
		))
	}

	// Use dns.MinMsgSize since 99% of DNS queries fit this size, so this is a
	// sensible default.
	c.UDPSize = cmp.Or(c.UDPSize, dns.MinMsgSize)
	c.TCPSize = cmp.Or(c.TCPSize, dns.MinMsgSize)

	c.Base.ListenConfig = cmp.Or(c.Base.ListenConfig, netext.DefaultListenConfigWithOOB(nil))

	s = &ServerDNS{
		ServerBase: newServerBase(proto, c.Base),

		udpPool:  syncutil.NewSlicePool[byte](c.UDPSize),
		tcpPool:  syncutil.NewSlicePool[byte](c.TCPSize),
		respPool: syncutil.NewSlicePool[byte](dns.MinMsgSize),

		tcpConns:   container.NewMapSet[net.Conn](),
		tcpConnsMu: &sync.Mutex{},

		readTimeout:    c.ReadTimeout,
		tcpIdleTimeout: c.TCPIdleTimeout,
		writeTimeout:   c.WriteTimeout,

		maxPipelineCount: c.MaxPipelineCount,

		maxUDPRespSize: max(c.MaxUDPRespSize, dns.MinMsgSize),

		maxPipelineEnabled: c.MaxPipelineEnabled,
	}

	s.taskPool = mustNewTaskPool(&taskPoolConfig{
		logger: s.baseLogger,
	})

	return s
}

// Start implements the dnsserver.Server interface for *ServerDNS.
func (s *ServerDNS) Start(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "starting dns server: %w") }()

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

	if s.proto != ProtoDNS {
		return ErrInvalidArgument
	}

	// Start listening to UDP on the specified address.
	if s.network.CanUDP() {
		err = s.listenUDP(ctx)
		if err != nil {
			return err
		}

		s.activeTaskWG.Go(func() {
			s.serveUDP(ctx, s.udpListener)
		})
	}

	// Start listening to TCP on the specified address.
	if s.network.CanTCP() {
		err = s.listenTCP(ctx)
		if err != nil {
			return err
		}

		s.activeTaskWG.Go(func() {
			s.serveTCP(ctx, s.tcpListener, "tcp")
		})
	}

	s.started = true

	s.baseLogger.InfoContext(ctx, "server has been started")

	return nil
}

// Shutdown implements the dnsserver.Server interface for *ServerDNS.
func (s *ServerDNS) Shutdown(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "shutting down dns server: %w") }()

	s.baseLogger.InfoContext(ctx, "shutting down server")

	err = s.shutdown(ctx)
	if err != nil {
		s.baseLogger.WarnContext(ctx, "error while shutting down", slogutil.KeyError, err)

		return err
	}

	s.unblockTCPConns(ctx)
	err = s.waitShutdown(ctx)

	// Close the workerPool and releases all workers.
	s.taskPool.Release()

	s.baseLogger.InfoContext(ctx, "server has been shut down")

	return err
}

// shutdown marks the server as stopped and closes active listeners.
func (s *ServerDNS) shutdown(ctx context.Context) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		return ErrServerNotStarted
	}

	// First, mark it as stopped.
	s.started = false

	// Now close all listeners.
	s.closeListeners(ctx)

	return nil
}

// unblockTCPConns unblocks reads for all active TCP connections.
func (s *ServerDNS) unblockTCPConns(ctx context.Context) {
	s.tcpConnsMu.Lock()
	defer s.tcpConnsMu.Unlock()

	s.tcpConns.Range(func(conn net.Conn) (cont bool) {
		err := conn.SetReadDeadline(time.Unix(1, 0))
		if err != nil {
			s.baseLogger.WarnContext(ctx, "failed to unblock conn", slogutil.KeyError, err)
		}

		return true
	})
}

// writeDeadlineSetter is an interface for connections that can set write
// deadlines.
type writeDeadlineSetter interface {
	SetWriteDeadline(t time.Time) (err error)
}

// withWriteDeadline is a helper that takes the deadline of the context and
// timeout into account.  It sets the write deadline on conn before calling f
// and resets it once f is done.
func withWriteDeadline(
	ctx context.Context,
	timeout time.Duration,
	conn writeDeadlineSetter,
	f func(),
) {
	// Add the given timeout and let context.WithTimeout decide which one is
	// sooner.
	ctx, cancel := context.WithTimeout(ctx, timeout)

	logger, ok := slogutil.LoggerFromContext(ctx)
	if !ok {
		logger = slogutil.NewDiscardLogger()
	}

	defer func() {
		cancel()

		err := conn.SetWriteDeadline(time.Time{})
		if err != nil && !errors.Is(err, net.ErrClosed) {
			// Consider deadline errors non-critical.  Ignore [net.ErrClosed] as
			// it is expected to happen when the client closes connections.
			logger.WarnContext(ctx, "removing deadlines", slogutil.KeyError, err)
		}
	}()

	// Since context.WithTimeout has been called, this should return a non-empty
	// deadline.
	dl, _ := ctx.Deadline()
	err := conn.SetWriteDeadline(dl)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		// Consider deadline errors non-critical.  Ignore [net.ErrClosed] as it
		// is expected to happen when the client closes connections.
		logger.WarnContext(ctx, "setting deadlines", slogutil.KeyError, err)
	}

	f()
}
