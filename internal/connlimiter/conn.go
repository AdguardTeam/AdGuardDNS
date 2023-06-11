package connlimiter

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/errors"
)

// limitConn is a wrapper for a stream connection that decreases the counter
// value on close.
//
// See https://pkg.go.dev/golang.org/x/net/netutil#LimitListener.
type limitConn struct {
	net.Conn

	decrement  func()
	start      time.Time
	serverInfo dnsserver.ServerInfo
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

	connLife := time.Since(c.start).Seconds()
	name := c.serverInfo.Name
	optlog.Debug3("connlimiter: %s: closed conn from %s after %fs", name, c.RemoteAddr(), connLife)
	metrics.StreamConnLifeDuration.WithLabelValues(
		name,
		c.serverInfo.Proto.String(),
		c.serverInfo.Addr,
	).Observe(connLife)

	c.decrement()

	return err
}
