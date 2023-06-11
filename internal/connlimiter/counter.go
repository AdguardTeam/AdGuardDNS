package connlimiter

// counter is the simultaneous stream-connection counter.  It stops accepting
// new connections once it reaches stop and resumes when the number of active
// connections goes back to resume.
//
// Note that current is the number of both active stream-connections as well as
// goroutines that are currently in the process of accepting a new connection
// but haven't accepted one yet.
type counter struct {
	current     uint64
	stop        uint64
	resume      uint64
	isAccepting bool
}

// increment tries to add the connection to the current active connection count.
// If the counter does not accept new connections, shouldAccept is false.
func (c *counter) increment() (shouldAccept bool) {
	if !c.isAccepting {
		return false
	}

	c.current++
	c.isAccepting = c.current < c.stop

	return true
}

// decrement decreases the number of current active connections.
func (c *counter) decrement() {
	c.current--

	c.isAccepting = c.isAccepting || c.current <= c.resume
}
