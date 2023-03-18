//go:build linux

package bindtodevice

import (
	"net"
	"sync"
)

// chanListener is a [net.Listener] that returns data sent to it through a
// channel.
//
// Listeners of this type are returned by [chanListenConfig.Listen] and are used
// in module dnsserver to make the bind-to-device logic work in DNS-over-TCP.
type chanListener struct {
	closeOnce *sync.Once
	conns     chan net.Conn
	laddr     net.Addr
}

// newChanListener returns a new properly initialized *chanListener.
func newChanListener(conns chan net.Conn, laddr net.Addr) (l *chanListener) {
	return &chanListener{
		closeOnce: &sync.Once{},
		conns:     conns,
		laddr:     laddr,
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
	closedNow := false
	l.closeOnce.Do(func() {
		close(l.conns)
		closedNow = true
	})

	if !closedNow {
		return wrapConnError(tnChanLsnr, "Close", l.laddr, net.ErrClosed)
	}

	return nil
}
