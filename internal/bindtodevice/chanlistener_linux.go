//go:build linux

package bindtodevice

import (
	"context"
	"net"
	"net/netip"
	"sync"
)

// chanListener is a [net.Listener] that returns data sent to it through a
// channel.
//
// Listeners of this type are returned by [ListenConfig.Listen] and are used in
// module dnsserver to make the bind-to-device logic work in DNS-over-TCP.
type chanListener struct {
	// mu protects conns (against closure) and isClosed.
	mu       *sync.Mutex
	conns    chan net.Conn
	metrics  Metrics
	laddr    net.Addr
	subnet   netip.Prefix
	isClosed bool
}

// newChanListener returns a new properly initialized *chanListener.  mtrc must
// not be nil.
func newChanListener(
	mtrc Metrics,
	conns chan net.Conn,
	subnet netip.Prefix,
	laddr net.Addr,
) (l *chanListener) {
	return &chanListener{
		mu:       &sync.Mutex{},
		conns:    conns,
		metrics:  mtrc,
		laddr:    laddr,
		subnet:   subnet,
		isClosed: false,
	}
}

// type check
var _ net.Listener = (*chanListener)(nil)

// Accept implements the [net.Listener] interface for *chanListener.
func (l *chanListener) Accept() (c net.Conn, err error) {
	var ok bool
	c, ok = <-l.conns
	if !ok {
		return nil, wrapConnError(tnChanLsnr, "Accept", l.laddr, net.ErrClosed)
	}

	return c, nil
}

// Addr implements the [net.Listener] interface for *chanListener.
func (l *chanListener) Addr() (addr net.Addr) { return l.laddr }

// Close implements the [net.Listener] interface for *chanListener.
func (l *chanListener) Close() (err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.isClosed {
		return wrapConnError(tnChanLsnr, "Close", l.laddr, net.ErrClosed)
	}

	close(l.conns)
	l.isClosed = true

	return nil
}

// send is a helper method to send a conn to the listener's channel.  ok is
// false if the listener is closed.
func (l *chanListener) send(ctx context.Context, conn net.Conn) (ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.isClosed {
		return false
	}

	l.conns <- conn

	l.metrics.SetTCPConnsChanSize(ctx, l.subnet, uint(len(l.conns)))

	return true
}
