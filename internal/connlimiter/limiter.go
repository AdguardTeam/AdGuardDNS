package connlimiter

import (
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
)

// Config is the configuration structure for the stream-connection limiter.
type Config struct {
	// Logger is used to log the operation of the limiter.  It must not be nil.
	Logger *slog.Logger

	// Stop is the point at which the limiter stops accepting new connections.
	// Once the number of active connections reaches this limit, new connections
	// wait for the number to decrease to or below Resume.
	//
	// Stop must be greater than zero and greater than or equal to Resume.
	Stop uint64

	// Resume is the point at which the limiter starts accepting new connections
	// again.
	//
	// Resume must be greater than zero and less than or equal to Stop.
	Resume uint64
}

// Limiter is the stream-connection limiter.
type Limiter struct {
	logger *slog.Logger

	// counterCond is the shared condition variable that protects counter.
	counterCond *sync.Cond

	// counter is the shared counter of active stream-connections.
	counter *counter
}

// New returns a new *Limiter.
func New(c *Config) (l *Limiter, err error) {
	if c == nil || c.Stop == 0 || c.Resume > c.Stop {
		return nil, fmt.Errorf("bad limiter config: %+v", c)
	}

	return &Limiter{
		logger:      c.Logger,
		counterCond: sync.NewCond(&sync.Mutex{}),
		counter: &counter{
			current:     0,
			stop:        c.Stop,
			resume:      c.Resume,
			isAccepting: true,
		},
	}, nil
}

// Limit wraps lsnr to control the number of active connections.  srvInfo is
// used for logging and metrics.
func (l *Limiter) Limit(lsnr net.Listener, srvInfo *dnsserver.ServerInfo) (limited net.Listener) {
	name, addr := srvInfo.Name, srvInfo.Addr
	proto := srvInfo.Proto.String()

	return &limitListener{
		Listener: lsnr,

		logger: l.logger.With("name", name),

		counterCond: l.counterCond,
		counter:     l.counter,

		serverInfo: srvInfo,

		activeGauge: metrics.ConnLimiterActiveStreamConns.WithLabelValues(name, proto, addr),
		waitingHist: metrics.StreamConnWaitDuration.WithLabelValues(name, proto, addr),

		isClosed: false,
	}
}
