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
	"github.com/AdguardTeam/golibs/syncutil"
)

// chanPacketConn is a [netext.SessionPacketConn] that returns data sent to it
// through the channel.
//
// Connections of this type are returned by [ListenConfig.ListenPacket] and are
// used in module dnsserver to make the bind-to-device logic work in UDP-based
// protocols
type chanPacketConn struct {
	// mu protects sessions (against closure) and isClosed.
	mu       *sync.Mutex
	sessions chan *packetSession

	writeRequests chan *packetConnWriteReq

	metrics Metrics

	// respPool is the pool used to dispose packet conn write responses.  It
	// must not be nil.
	respPool *syncutil.Pool[packetConnWriteResp]

	// reqPool is the pool used to dispose packet conn write requests.  It must
	// not be nil.
	reqPool *syncutil.Pool[packetConnWriteReq]

	// bodyPool is the pool used to dispose of read bodies after they've been
	// copied.  It must not be nil.
	bodyPool *syncutil.Pool[[]byte]

	deadlineRead  *dynamicDeadline
	deadlineWrite *dynamicDeadline

	laddr    net.Addr
	subnet   netip.Prefix
	id       ID
	isClosed bool
}

// newChanPacketConn returns a new properly initialized *chanPacketConn.  mtrc,
// sessions, respPool, reqPool, bodyPool, writeRequests, and laddr must not be
// nil.
//
// TODO(a.garipov):  Consider adding a config structure.
func newChanPacketConn(
	mtrc Metrics,
	sessions chan *packetSession,
	respPool *syncutil.Pool[packetConnWriteResp],
	reqPool *syncutil.Pool[packetConnWriteReq],
	bodyPool *syncutil.Pool[[]byte],
	subnet netip.Prefix,
	writeRequests chan *packetConnWriteReq,
	id ID,
	laddr net.Addr,
) (c *chanPacketConn) {
	return &chanPacketConn{
		mu:            &sync.Mutex{},
		sessions:      sessions,
		writeRequests: writeRequests,

		metrics: mtrc,

		respPool: respPool,
		reqPool:  reqPool,
		bodyPool: bodyPool,

		deadlineRead:  newDynamicDeadline(),
		deadlineWrite: newDynamicDeadline(),

		laddr:  laddr,
		subnet: subnet,

		id: id,
	}
}

// packetConnWriteReq is a request to write a piece of data to the original
// packet connection.  respCh, bodyPtr, and either raddr or session must be set.
type packetConnWriteReq struct {
	respCh   chan *packetConnWriteResp
	bodyPtr  *[]byte
	session  *packetSession
	raddr    net.Addr
	deadline time.Time
}

// reset makes *packetConnWriteReq ready for reuse.
func (r *packetConnWriteReq) reset() {
	*r = packetConnWriteReq{}
}

// packetConnWriteResp is a response to a [packetConnWriteReq].
type packetConnWriteResp struct {
	err error
	n   int
}

// reset makes *packetConnWriteResp ready for reuse.
func (r *packetConnWriteResp) reset() {
	*r = packetConnWriteResp{}
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
	n, s, err := c.readFromSession(b, "ReadFrom")
	if s == nil {
		return n, nil, err
	}

	raddr = &sessionAddr{
		session: s,
	}

	return n, raddr, err
}

// ReadFromSession implements the [netext.SessionPacketConn] interface for
// *chanPacketConn.
func (c *chanPacketConn) ReadFromSession(b []byte) (n int, s netext.PacketSession, err error) {
	n, sess, err := c.readFromSession(b, "ReadFromSession")
	if sess == nil {
		// Shouldn't happen unless there is an error.  Also, return a literal
		// nil to prevent netext.PacketSession((*packetSession)(nil)).
		return n, nil, err
	}

	return n, sess, err
}

// readFromSession contains the common code of [chanPacketConn.ReadFrom] and
// [chanPacketConn.ReadFromSession].
func (c *chanPacketConn) readFromSession(
	b []byte,
	fnName string,
) (n int, s *packetSession, err error) {
	defer func() {
		if s == nil {
			return
		}

		n = copy(b, *s.readBodyPtr)
		c.bodyPool.Put(s.readBodyPtr)

		// Remove this reference to prevent misuse.
		s.readBodyPtr = nil
	}()

	timerCh, _ := c.deadlineRead.wait()

	s, err = receiveWithTimer(c.sessions, timerCh)
	if err != nil {
		err = fmt.Errorf("receiving: %w", err)

		return 0, s, wrapConnError(tnChanPConn, fnName, c.laddr, err)
	}

	return 0, s, nil
}

// SetDeadline implements the [netext.SessionPacketConn] interface for
// *chanPacketConn.  It always returns nil.
func (c *chanPacketConn) SetDeadline(t time.Time) (err error) {
	c.deadlineRead.set(t)
	c.deadlineWrite.set(t)

	return nil
}

// SetReadDeadline implements the [netext.SessionPacketConn] interface for
// *chanPacketConn.  It always returns nil.
func (c *chanPacketConn) SetReadDeadline(t time.Time) (err error) {
	c.deadlineRead.set(t)

	return nil
}

// SetWriteDeadline implements the [netext.SessionPacketConn] interface for
// *chanPacketConn.  It always returns nil.
func (c *chanPacketConn) SetWriteDeadline(t time.Time) (err error) {
	c.deadlineWrite.set(t)

	return nil
}

// WriteTo implements the [netext.SessionPacketConn] interface for
// *chanPacketConn.  raddr must not be nil.
func (c *chanPacketConn) WriteTo(b []byte, raddr net.Addr) (n int, err error) {
	var s *packetSession
	if a, ok := raddr.(*sessionAddr); ok {
		s = a.session
	}

	// Don't wrap the error, because [chanPacketConn.writeToSession] is the
	// common method containing all error handling.
	return c.writeToSession(b, s, raddr, "WriteTo")
}

// WriteToSession implements the [netext.SessionPacketConn] interface for
// *chanPacketConn.  s must not be nil.
func (c *chanPacketConn) WriteToSession(b []byte, s netext.PacketSession) (n int, err error) {
	// Don't wrap the error, because [chanPacketConn.writeToSession] is the
	// common method containing all error handling.
	return c.writeToSession(b, s.(*packetSession), nil, "WriteToSession")
}

// writeToSession contains the common code of [chanPacketConn.WriteTo] and
// [chanPacketConn.WriteToSession].  Either raddr or s must not be nil.
func (c *chanPacketConn) writeToSession(
	b []byte,
	s *packetSession,
	raddr net.Addr,
	fnName string,
) (n int, err error) {
	timerCh, dl := c.deadlineWrite.wait()

	resp := make(chan *packetConnWriteResp, 1)

	// NOTE: Request is returned to the pool in
	// [interfaceListener.writeUDPResponses].
	req := c.reqPool.Get()
	req.reset()

	req.respCh = resp
	req.session = s
	req.raddr = raddr

	// TODO(a.garipov):  The deadline might change while the write is still
	// in progress.  Consider if this is dangerous in practice and find ways
	// of solving it.
	req.deadline = dl

	// Copy the body to prevent data races, since [io.Writer] implementations
	// shouldn't retain the original slices.
	bodyPtr := c.bodyPool.Get()
	(*bodyPtr) = append((*bodyPtr)[:0], b...)

	// Returned to the pool in [interfaceListener.writeUDPResponses].
	req.bodyPtr = bodyPtr

	err = sendWithTimer(c.writeRequests, req, timerCh)
	if err != nil {
		c.bodyPool.Put(bodyPtr)
		c.reqPool.Put(req)

		err = fmt.Errorf("sending write request: %w", err)

		return 0, wrapConnError(tnChanPConn, fnName, c.laddr, err)
	}

	// TODO(s.chzhen):  Pass context.
	c.metrics.SetUDPWriteRequestsChanSize(context.TODO(), string(c.id), uint(len(c.writeRequests)))

	// TODO(a.garipov):  Make this more robust to prevent this blocking forever
	// during a shutdown.
	r, err := receiveWithTimer(resp, timerCh)
	if err != nil {
		return 0, wrapConnError(tnChanPConn, fnName, c.laddr, err)
	}
	defer c.respPool.Put(r)

	return r.n, r.err
}

// receiveWithTimer is a helper function that uses a timer channel to indicate
// that a receive did not succeed in time.  If the channel is closed, err is
// [net.ErrClosed].  Otherwise, if the receive from timerCh succeeded, err is
// [os.ErrDeadlineExceeded].
func receiveWithTimer[T any](ch <-chan T, timerCh <-chan unit) (v T, err error) {
	// TODO(a.garipov):  There could technically be a race here when both
	// operations can proceed.  There is also a case where the channel has been
	// closed but it still contains sent data.  Consider these cases rare and,
	// if this proves to ever become problematic, use a select-within-select
	// idiom to detect such situations and process in a stable manner.
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
// a send did not succeed in time.  If the receive from timerCh succeeded, err
// is [os.ErrDeadlineExceeded].
func sendWithTimer[T any](ch chan<- T, v T, timerCh <-chan unit) (err error) {
	// TODO(a.garipov):  There could technically be a race here when both
	// operations can proceed.  Consider this a rare case and, if this proves to
	// ever become problematic, use a select-within-select idiom to detect such
	// situations and process in a stable manner.
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

	// TODO(a.garipov):  Make this more robust so that a send to a full buffer
	// and [chanPacketConn.Close] don't ever cause a deadlock.
	c.sessions <- sess

	c.metrics.SetUDPSessionsChanSize(ctx, c.subnet, uint(len(c.sessions)))

	return true
}
