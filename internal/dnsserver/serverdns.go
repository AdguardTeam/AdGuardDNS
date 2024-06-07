package dnsserver

import (
	"cmp"
	"context"
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
	"github.com/panjf2000/ants/v2"
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
)

// ConfigDNS is a struct that needs to be passed to NewServerDNS to
// initialize a new ServerDNS instance.
type ConfigDNS struct {
	ConfigBase

	// ReadTimeout is the net.Conn.SetReadTimeout value for new connections.
	// If not set it defaults to DefaultReadTimeout.
	ReadTimeout time.Duration

	// WriteTimeout is the net.Conn.SetWriteTimeout value for connections.  If
	// not set it defaults to DefaultWriteTimeout.
	WriteTimeout time.Duration

	// UDPSize is the size of the buffers used to read incoming UDP messages.
	// If not set it defaults to [dns.MinMsgSize], 512 B.
	UDPSize int

	// TCPSize is the initial size of the buffers used to read incoming TCP
	// messages.  If not set it defaults to [dns.MinMsgSize], 512 B.
	TCPSize int

	// MaxUDPRespSize is the maximum size of DNS response over UDP protocol.
	MaxUDPRespSize uint16

	// TCPIdleTimeout is the timeout for waiting between multiple queries.  If
	// not set it defaults to [DefaultTCPIdleTimeout].
	TCPIdleTimeout time.Duration

	// MaxPipelineCount is the maximum number of simultaneously processing TCP
	// messages per one connection.  If MaxPipelineEnabled is true, it must be
	// greater than zero.
	MaxPipelineCount uint

	// MaxPipelineEnabled, if true, enables TCP pipeline limiting.
	MaxPipelineEnabled bool
}

// ServerDNS is a plain DNS server (e.g. it supports UDP and TCP protocols).
type ServerDNS struct {
	*ServerBase

	// workerPool is a goroutine workerPool we use to process DNS queries.
	// Complicated logic may require growing the goroutine's stack, and we
	// experienced it in AdGuard DNS.  The easiest way to avoid spending extra
	// time on this is to reuse already existing goroutines.
	workerPool *ants.Pool

	// udpPool is a pool for UDP request buffers.
	udpPool *syncutil.Pool[[]byte]

	// tcpPool is a pool for TCP request buffers.
	tcpPool *syncutil.Pool[[]byte]

	// respPool is a pool for response buffers.
	respPool *syncutil.Pool[[]byte]

	// tcpConns is a set that is used to track active connections.
	tcpConns   map[net.Conn]struct{}
	tcpConnsMu *sync.Mutex

	// TODO(ameshkov, a.garipov):  Only save the parameters a server actually
	// needs.
	conf ConfigDNS
}

// type check
var _ Server = (*ServerDNS)(nil)

// NewServerDNS creates a new ServerDNS instance.
func NewServerDNS(conf ConfigDNS) (s *ServerDNS) {
	return newServerDNS(ProtoDNS, conf)
}

// newServerDNS initializes a new ServerDNS instance with the specified proto.
// This function is reused in ServerTLS as it is basically a plain DNS-over-TCP
// server with a TLS layer on top of it.
func newServerDNS(proto Protocol, conf ConfigDNS) (s *ServerDNS) {
	// Init default settings first.
	conf.ReadTimeout = cmp.Or(conf.ReadTimeout, DefaultReadTimeout)
	conf.WriteTimeout = cmp.Or(conf.WriteTimeout, DefaultWriteTimeout)
	conf.TCPIdleTimeout = cmp.Or(conf.TCPIdleTimeout, DefaultTCPIdleTimeout)

	// Use dns.MinMsgSize since 99% of DNS queries fit this size, so this is a
	// sensible default.
	conf.UDPSize = cmp.Or(conf.UDPSize, dns.MinMsgSize)
	conf.TCPSize = cmp.Or(conf.TCPSize, dns.MinMsgSize)

	if conf.ListenConfig == nil {
		conf.ListenConfig = netext.DefaultListenConfigWithOOB(nil)
	}

	s = &ServerDNS{
		ServerBase: newServerBase(proto, conf.ConfigBase),
		workerPool: newPoolNonblocking(),

		udpPool:  syncutil.NewSlicePool[byte](conf.UDPSize),
		tcpPool:  syncutil.NewSlicePool[byte](conf.TCPSize),
		respPool: syncutil.NewSlicePool[byte](dns.MinMsgSize),

		tcpConns:   map[net.Conn]struct{}{},
		tcpConnsMu: &sync.Mutex{},

		conf: conf,
	}

	return s
}

// Start implements the dnsserver.Server interface for *ServerDNS.
func (s *ServerDNS) Start(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "starting dns server: %w") }()

	s.lock.Lock()
	defer s.lock.Unlock()

	if s.started {
		return ErrServerAlreadyStarted
	}

	log.Info("[%s]: Starting the server", s.Name())

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

		s.wg.Add(1)
		go s.startServeUDP(ctx)
	}

	// Start listening to TCP on the specified address.
	if s.network.CanTCP() {
		err = s.listenTCP(ctx)
		if err != nil {
			return err
		}

		s.wg.Add(1)
		go s.startServeTCP(ctx)
	}

	s.started = true

	log.Info("[%s]: Server has been started", s.Name())

	return nil
}

// Shutdown implements the dnsserver.Server interface for *ServerDNS.
func (s *ServerDNS) Shutdown(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "shutting down dns server: %w") }()

	err = s.shutdown()
	if err != nil {
		log.Info("[%s]: Failed to shutdown: %v", s.Name(), err)

		return err
	}

	s.unblockTCPConns()
	err = s.waitShutdown(ctx)

	// Close the workerPool and releases all workers.
	s.workerPool.Release()

	log.Info("[%s]: Finished stopping the server", s.Name())

	return err
}

// startServeUDP starts the UDP listener loop.
func (s *ServerDNS) startServeUDP(ctx context.Context) {
	// Do not recover from panics here since if this goroutine panics, the
	// application won't be able to continue listening to UDP.
	defer s.handlePanicAndExit(ctx)
	defer s.wg.Done()

	log.Info("[%s]: Start listening to udp://%s", s.Name(), s.Addr())
	err := s.serveUDP(ctx, s.udpListener)
	if err != nil {
		log.Info("[%s]: Finished listening to udp://%s due to %v", s.Name(), s.Addr(), err)
	}
}

// startServeTCP starts the TCP listener loop.
func (s *ServerDNS) startServeTCP(ctx context.Context) {
	// Do not recover from panics here since if this goroutine panics, the
	// application won't be able to continue listening to TCP.
	defer s.handlePanicAndExit(ctx)
	defer s.wg.Done()

	log.Info("[%s]: Start listening to tcp://%s", s.Name(), s.Addr())
	err := s.serveTCP(ctx, s.tcpListener)
	if err != nil {
		log.Info("[%s]: Finished listening to tcp://%s due to %v", s.Name(), s.Addr(), err)
	}
}

// shutdown marks the server as stopped and closes active listeners.
func (s *ServerDNS) shutdown() (err error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if !s.started {
		return ErrServerNotStarted
	}

	// First, mark it as stopped.
	s.started = false

	// Now close all listeners.
	s.closeListeners()

	return nil
}

// unblockTCPConns unblocks reads for all active TCP connections.
func (s *ServerDNS) unblockTCPConns() {
	s.tcpConnsMu.Lock()
	defer s.tcpConnsMu.Unlock()
	for conn := range s.tcpConns {
		err := conn.SetReadDeadline(time.Unix(1, 0))
		if err != nil {
			log.Debug("[%s]: Failed to set read deadline: %v", s.Name(), err)
		}
	}
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

	defer func() {
		cancel()

		err := conn.SetWriteDeadline(time.Time{})
		if err != nil && !errors.Is(err, net.ErrClosed) {
			// Consider deadline errors non-critical.  Ignore [net.ErrClosed] as
			// it is expected to happen when the client closes connections.
			log.Error("dnsserver: removing deadlines: %s", err)
		}
	}()

	// Since context.WithTimeout has been called, this should return a non-empty
	// deadline.
	dl, _ := ctx.Deadline()
	err := conn.SetWriteDeadline(dl)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		// Consider deadline errors non-critical.  Ignore [net.ErrClosed] as it
		// is expected to happen when the client closes connections.
		log.Error("dnsserver: setting deadlines: %s", err)
	}

	f()
}
