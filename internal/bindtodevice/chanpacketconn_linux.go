//go:build linux

package bindtodevice

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
)

// chanPacketConn is a [netext.SessionPacketConn] that returns data sent to it
// through the channel.
//
// Connections of this type are returned by [chanListenConfig.ListenPacket] and
// are used in module dnsserver to make the bind-to-device logic work in
// DNS-over-UDP.
type chanPacketConn struct {
	closeOnce *sync.Once
	sessions  chan *packetSession
	laddr     net.Addr

	// deadlineMu protects readDeadline and writeDeadline.
	deadlineMu    *sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time

	writeRequests chan *packetConnWriteReq
}

// newChanPacketConn returns a new properly initialized *chanPacketConn.
func newChanPacketConn(
	sessions chan *packetSession,
	writeRequests chan *packetConnWriteReq,
	laddr net.Addr,
) (c *chanPacketConn) {
	return &chanPacketConn{
		closeOnce: &sync.Once{},
		sessions:  sessions,
		laddr:     laddr,

		deadlineMu: &sync.RWMutex{},

		writeRequests: writeRequests,
	}
}

// packetConnWriteReq is a request to write a piece of data to the original
// packet connection.  resp, body, and either raddr or session must be set.
type packetConnWriteReq struct {
	resp     chan *packetConnWriteResp
	session  *packetSession
	raddr    net.Addr
	deadline time.Time
	body     []byte
}

// packetConnWriteResp is a response to a [packetConnWriteReq].
type packetConnWriteResp struct {
	err     error
	written int
}

// type check
var _ netext.SessionPacketConn = (*chanPacketConn)(nil)

// Close implements the [netext.SessionPacketConn] interface for
// *chanPacketConn.
func (c *chanPacketConn) Close() (err error) {
	closedNow := false
	c.closeOnce.Do(func() {
		close(c.sessions)
		closedNow = true
	})

	if !closedNow {
		return wrapConnError(tnChanPConn, "Close", c.laddr, net.ErrClosed)
	}

	return nil
}

// LocalAddr implements the [netext.SessionPacketConn] interface for
// *chanPacketConn.
func (c *chanPacketConn) LocalAddr() (addr net.Addr) { return c.laddr }

// ReadFrom implements the [netext.SessionPacketConn] interface for
// *chanPacketConn.
func (c *chanPacketConn) ReadFrom(b []byte) (n int, raddr net.Addr, err error) {
	n, sess, err := c.readFromSession(b, "ReadFrom")

	return n, sess.RemoteAddr(), err
}

// ReadFromSession implements the [netext.SessionPacketConn] interface for
// *chanPacketConn.
func (c *chanPacketConn) ReadFromSession(b []byte) (n int, s netext.PacketSession, err error) {
	return c.readFromSession(b, "ReadFromSession")
}

// readFromSession contains the common code of [ReadFrom] and [ReadFromSession].
func (c *chanPacketConn) readFromSession(
	b []byte,
	fnName string,
) (n int, s netext.PacketSession, err error) {
	var deadline time.Time
	func() {
		c.deadlineMu.RLock()
		defer c.deadlineMu.RUnlock()

		deadline = c.readDeadline
	}()

	timerCh, stopTimer, err := timerFromDeadline(deadline)
	if err != nil {
		err = fmt.Errorf("setting deadline: %w", err)

		return 0, nil, wrapConnError(tnChanPConn, fnName, c.laddr, err)
	}
	defer stopTimer()

	sess, err := receiveWithTimer(c.sessions, timerCh)
	if err != nil {
		err = fmt.Errorf("receiving: %w", err)

		return 0, nil, wrapConnError(tnChanPConn, fnName, c.laddr, err)
	}

	n = copy(b, sess.readBody)

	return n, sess, nil
}

// timerFromDeadline converts a deadline value into a timer channel.  stopTimer
// must be deferred by the caller.
func timerFromDeadline(deadline time.Time) (timerCh <-chan time.Time, stopTimer func(), err error) {
	if deadline.IsZero() {
		return nil, func() {}, nil
	}

	d := time.Until(deadline)
	if d <= 0 {
		return nil, func() {}, os.ErrDeadlineExceeded
	}

	timer := time.NewTimer(time.Until(deadline))
	timerCh = timer.C
	stopTimer = func() {
		if !timer.Stop() {
			// We don't know if the timer's value has been consumed yet or not,
			// so use a select with default to make sure that this doesn't
			// block.
			select {
			case <-timerCh:
			default:
			}
		}
	}

	return timerCh, stopTimer, nil
}

// SetDeadline implements the [netext.SessionPacketConn] interface for
// *chanPacketConn.
func (c *chanPacketConn) SetDeadline(t time.Time) (err error) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()

	c.readDeadline = t
	c.writeDeadline = t

	return nil
}

// SetReadDeadline implements the [netext.SessionPacketConn] interface for
// *chanPacketConn.
func (c *chanPacketConn) SetReadDeadline(t time.Time) (err error) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()

	c.readDeadline = t

	return nil
}

// SetWriteDeadline implements the [netext.SessionPacketConn] interface for
// *chanPacketConn.
func (c *chanPacketConn) SetWriteDeadline(t time.Time) (err error) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()

	c.writeDeadline = t

	return nil
}

// WriteTo implements the [netext.SessionPacketConn] interface for
// *chanPacketConn.
func (c *chanPacketConn) WriteTo(b []byte, raddr net.Addr) (n int, err error) {
	return c.writeToSession(b, nil, raddr, "WriteTo")
}

// WriteToSession implements the [netext.SessionPacketConn] interface for
// *chanPacketConn.
func (c *chanPacketConn) WriteToSession(
	b []byte,
	s netext.PacketSession,
) (n int, err error) {
	return c.writeToSession(b, s.(*packetSession), nil, "WriteToSession")
}

// writeToSession contains the common code of [WriteTo] and [WriteToSession].
func (c *chanPacketConn) writeToSession(
	b []byte,
	s *packetSession,
	raddr net.Addr,
	fnName string,
) (n int, err error) {
	var deadline time.Time
	func() {
		c.deadlineMu.RLock()
		defer c.deadlineMu.RUnlock()

		deadline = c.writeDeadline
	}()

	timerCh, stopTimer, err := timerFromDeadline(deadline)
	if err != nil {
		err = fmt.Errorf("setting deadline: %w", err)

		return 0, wrapConnError(tnChanPConn, fnName, c.laddr, err)
	}
	defer stopTimer()

	resp := make(chan *packetConnWriteResp, 1)
	req := &packetConnWriteReq{
		resp:     resp,
		session:  s,
		raddr:    raddr,
		deadline: deadline,
		body:     b,
	}
	err = sendWithTimer(c.writeRequests, req, timerCh)
	if err != nil {
		err = fmt.Errorf("sending write request: %w", err)

		return 0, wrapConnError(tnChanPConn, fnName, c.laddr, err)
	}

	r, err := receiveWithTimer(resp, timerCh)
	if err != nil {
		err = fmt.Errorf("receiving write response: %w", err)

		return 0, wrapConnError(tnChanPConn, fnName, c.laddr, err)
	}

	return r.written, r.err
}

// receiveWithTimer is a helper function that uses a timer channel to indicate
// that a receive did not succeed in time.  If the channel is closed, err is
// [net.ErrClosed].  If the receive from timerCh succeeded first, err is
// [os.ErrDeadlineExceeded].
func receiveWithTimer[T any](ch <-chan T, timerCh <-chan time.Time) (v T, err error) {
	var ok bool
	select {
	case v, ok = <-ch:
		if !ok {
			err = net.ErrClosed
		}
	case <-timerCh:
		err = os.ErrDeadlineExceeded
	}

	return v, err
}

// sendWithTimer is a helper function that uses a timer channel to indicate that
// a send did not succeed in time.  If the receive from timerCh succeeded first,
// err is [os.ErrDeadlineExceeded].
func sendWithTimer[T any](ch chan<- T, v T, timerCh <-chan time.Time) (err error) {
	select {
	case ch <- v:
		return nil
	case <-timerCh:
		return os.ErrDeadlineExceeded
	}
}
