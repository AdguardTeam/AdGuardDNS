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

// wrapConn wraps a net.Conn in a Conn instance.
func wrapConn(conn net.Conn) (c *Conn) {
	return &Conn{
		Conn:         conn,
		lastTimeUsed: time.Now(),
	}
}

// isExpired checks if the connection has expired.
func isExpired(conn *Conn, timeout time.Duration) (exp bool) {
	return timeout > 0 &&
		time.Since(conn.lastTimeUsed) > timeout
}
