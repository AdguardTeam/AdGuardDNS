package tlsconfig

import (
	"net"
	"net/netip"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/fakenet"
)

// testLogger is the common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

// NewAddrConn returns a new [net.Conn] that has only the LocalAddr and
// RemoteAddr methods implemented, which return addr and a TCP address for
// "192.0.2.123" correspondingly.
//
// TODO(a.garipov):  Add fakenet.NewConn.
func NewAddrConn(addr netip.Addr) (c *fakenet.Conn) {
	return &fakenet.Conn{
		OnLocalAddr: func() (a net.Addr) {
			return net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr, 0))
		},
		OnRemoteAddr: func() (a net.Addr) {
			return &net.TCPAddr{
				IP:   net.IP{192, 0, 2, 123},
				Port: 12345,
			}
		},
		OnClose:            func() (err error) { panic(testutil.UnexpectedCall()) },
		OnRead:             func(b []byte) (n int, err error) { panic(testutil.UnexpectedCall()) },
		OnWrite:            func(b []byte) (n int, err error) { panic(testutil.UnexpectedCall()) },
		OnSetDeadline:      func(t time.Time) (err error) { panic(testutil.UnexpectedCall()) },
		OnSetReadDeadline:  func(t time.Time) (err error) { panic(testutil.UnexpectedCall()) },
		OnSetWriteDeadline: func(t time.Time) (err error) { panic(testutil.UnexpectedCall()) },
	}
}
