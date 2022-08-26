package dnsserver

import (
	"crypto/tls"
	"net"
)

// tlsListener is the implementation of net.Listener that accepts tls.Conn.
// The only point of using our own implementation is to close underlying TCP
// connections gracefully.
// The bug itself is described here: https://github.com/golang/go/issues/45709.
type tlsListener struct {
	tcp       net.Listener
	tlsConfig *tls.Config
}

// newTLSListener creates a new instance of tlsListener.
func newTLSListener(l net.Listener, tlsConfig *tls.Config) (tlsListen *tlsListener) {
	return &tlsListener{
		tcp:       l,
		tlsConfig: tlsConfig,
	}
}

// type check
var _ net.Listener = (*tlsListener)(nil)

// Accept implements the net.Listener interface for *tlsListener.
func (l *tlsListener) Accept() (conn net.Conn, err error) {
	var c net.Conn
	c, err = l.tcp.Accept()
	if err != nil {
		return nil, err
	}
	conn = &tlsConn{
		Conn:     tls.Server(c, l.tlsConfig),
		baseConn: c,
	}
	return conn, nil
}

// Close implements the net.Listener interface for *tlsListener.
func (l *tlsListener) Close() (err error) {
	return l.tcp.Close()
}

// Addr implements the net.Listener interface for *tlsListener.
func (l *tlsListener) Addr() (addr net.Addr) {
	return l.tcp.Addr()
}

// tlsConn is the implementation of net.Conn with a minuscule change
// When "Close" method is called, it closes underlying connection instead
// of sending the TLS close_notify alert.
type tlsConn struct {
	*tls.Conn
	baseConn net.Conn // underlying TCP connection
}

// type check
var _ net.Conn = (*tlsConn)(nil)

// Close implements the net.Conn interface for *tlsConn.
// It changes the basic logic in order to fix this issue:
// https://github.com/golang/go/issues/45709
func (c *tlsConn) Close() (err error) {
	return c.baseConn.Close()
}
