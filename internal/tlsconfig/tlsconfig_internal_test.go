package tlsconfig

import (
	"net"
	"net/netip"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/fakenet"
)

// NewLocalAddrConn returns a new [net.Conn] that has only the LocalAddr method
// implemented, which returns addr.
//
// TODO(a.garipov):  Add fakenet.NewConn.
func NewLocalAddrConn(addr netip.Addr) (c *fakenet.Conn) {
	return &fakenet.Conn{
		OnLocalAddr: func() (a net.Addr) {
			return net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr, 0))
		},
		OnRemoteAddr:       func() (a net.Addr) { panic(testutil.UnexpectedCall()) },
		OnClose:            func() (err error) { panic(testutil.UnexpectedCall()) },
		OnRead:             func(b []byte) (n int, err error) { panic(testutil.UnexpectedCall()) },
		OnWrite:            func(b []byte) (n int, err error) { panic(testutil.UnexpectedCall()) },
		OnSetDeadline:      func(t time.Time) (err error) { panic(testutil.UnexpectedCall()) },
		OnSetReadDeadline:  func(t time.Time) (err error) { panic(testutil.UnexpectedCall()) },
		OnSetWriteDeadline: func(t time.Time) (err error) { panic(testutil.UnexpectedCall()) },
	}
}
