package connlimiter

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/optslog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
)

// limitConn is a wrapper for a stream connection that decreases the counter
// value on close.
//
// See https://pkg.go.dev/golang.org/x/net/netutil#LimitListener.
type limitConn struct {
	net.Conn

	logger     *slog.Logger
	serverInfo *dnsserver.ServerInfo
	decrement  func()
	start      time.Time
	isClosed   atomic.Bool
}

// Close closes the underlying connection and decrements the counter.
func (c *limitConn) Close() (err error) {
	defer func() { err = errors.Annotate(err, "limit conn: %w") }()

	if !c.isClosed.CompareAndSwap(false, true) {
		return net.ErrClosed
	}

	// Close the connection immediately and wait for the counter decrement and
	// metrics later.
	err = c.Conn.Close()

	ctx := context.Background()
	connLife := time.Since(c.start)
	optslog.Debug2(
		ctx,
		c.logger,
		"closed conn",
		"raddr", c.RemoteAddr(),
		"conn_life", timeutil.Duration{
			Duration: connLife,
		},
	)
	metrics.StreamConnLifeDuration.WithLabelValues(
		c.serverInfo.Name,
		c.serverInfo.Proto.String(),
		c.serverInfo.Addr,
	).Observe(connLife.Seconds())

	c.decrement()

	return err
}
