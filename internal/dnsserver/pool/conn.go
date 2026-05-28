package pool

import (
	"net"
	"time"
)

// Conn wraps a net.Conn and contains additional info that could be required
// by the Pool instance.  It can be used directly instead of a net.Conn or you
// may choose to use the underlying Conn.Conn instead.
type Conn struct {
	net.Conn

	// lastTimeUsed is the last time when this connection was used, i.e.
	// requested from the pool.
	lastTimeUsed time.Time
}

// wrapConn wraps a net.Conn in a Conn instance.  lastUsed is the time when the
// connection was last used.
func wrapConn(conn net.Conn, lastUsed time.Time) (c *Conn) {
	return &Conn{
		Conn:         conn,
		lastTimeUsed: lastUsed,
	}
}

// isExpired checks if the connection has expired.  now is the current time used
// to compare against the connection's last-used time.
func isExpired(conn *Conn, timeout time.Duration, now time.Time) (exp bool) {
	return timeout > 0 && now.Sub(conn.lastTimeUsed) > timeout
}
