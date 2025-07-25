//go:build linux

package bindtodevice

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
)

// chanPacketConn is a [netext.SessionPacketConn] that returns data sent to it
// through the channel.
//
// Connections of this type are returned by [ListenConfig.ListenPacket] and are
// used in module dnsserver to make the bind-to-device logic work in
// DNS-over-UDP.
type chanPacketConn struct {
	// mu protects sessions (against closure) and isClosed.
	mu       *sync.Mutex
	sessions chan *packetSession

	writeRequests chan *packetConnWriteReq

	metrics Metrics

	// deadlineMu protects readDeadline and writeDeadline.
	deadlineMu    *sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time

	laddr     net.Addr
	subnet    netip.Prefix
	ifaceName string
	isClosed  bool
}

// newChanPacketConn returns a new properly initialized *chanPacketConn.  mtrc
// must not be nil.
func newChanPacketConn(
	mtrc Metrics,
	sessions chan *packetSession,
	subnet netip.Prefix,
	writeRequests chan *packetConnWriteReq,
	ifaceName string,
	laddr net.Addr,
) (c *chanPacketConn) {
	return &chanPacketConn{
		mu:            &sync.Mutex{},
		sessions:      sessions,
		writeRequests: writeRequests,

		metrics: mtrc,

		deadlineMu: &sync.RWMutex{},

		laddr:  laddr,
		subnet: subnet,

		ifaceName: ifaceName,
	}
}

// packetConnWriteReq is a request to write a piece of data to the original
// packet connection.  respCh, body, and either raddr or session must be set.
type packetConnWriteReq struct {
	respCh   chan *packetConnWriteResp
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
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return wrapConnError(tnChanPConn, "Close", c.laddr, net.ErrClosed)
	}

	close(c.sessions)
	c.isClosed = true

	return nil
}

// LocalAddr implements the [netext.SessionPacketConn] interface for
// *chanPacketConn.
func (c *chanPacketConn) LocalAddr() (addr net.Addr) { return c.laddr }

// ReadFrom implements the [netext.SessionPacketConn] interface for
// *chanPacketConn.
func (c *chanPacketConn) ReadFrom(b []byte) (n int, raddr net.Addr, err error) {
	n, sess, err := c.readFromSession(b, "ReadFrom")
	if sess == nil {
		return 0, nil, err
	}

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
	var sess *packetSession
	defer func() {
		if sess != nil {
			n = copy(b, sess.readBody)
		}
	}()

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

	sess, err = receiveWithTimer(c.sessions, timerCh)
	if err != nil {
		err = fmt.Errorf("receiving: %w", err)

		// Prevent netext.PacketSession((*packetSession)(nil)).
		if sess != nil {
			s = sess
		}

		return 0, s, wrapConnError(tnChanPConn, fnName, c.laddr, err)
	}

	return 0, sess, nil
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
		respCh:   resp,
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

	// TODO(s.chzhen):  Pass context.
	c.metrics.SetUDPWriteRequestsChanSize(context.TODO(), c.ifaceName, uint(len(c.writeRequests)))

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

// send is a helper method to send a session to the packet connection's channel.
// ok is false if the listener is closed.
func (c *chanPacketConn) send(ctx context.Context, sess *packetSession) (ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return false
	}

	c.sessions <- sess

	c.metrics.SetUDPSessionsChanSize(ctx, c.subnet, uint(len(c.sessions)))

	return true
}
