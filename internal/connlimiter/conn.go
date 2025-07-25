package connlimiter

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/optslog"
)

// limitConn is a wrapper for a stream connection that decreases the counter
// value on close.
//
// See https://pkg.go.dev/golang.org/x/net/netutil#LimitListener.
type limitConn struct {
	net.Conn

	connInfo  *ConnMetricsData
	logger    *slog.Logger
	metrics   Metrics
	decrement func(ctx context.Context)
	start     time.Time
	isClosed  atomic.Bool
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
	optslog.Trace2(ctx, c.logger, "closed conn", "raddr", c.RemoteAddr(), "conn_life", connLife)

	c.metrics.ObserveLifeDuration(ctx, c.connInfo, connLife)

	c.decrement(ctx)

	return err
}
