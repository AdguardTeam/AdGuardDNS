package connlimiter_test

import (
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/connlimiter"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/fakenet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is the common timeout for tests.
const testTimeout = 1 * time.Second

// testServerInfo is the common server information for tests.
var testServerInfo = &dnsserver.ServerInfo{
	Name:  "test_server",
	Addr:  "127.0.0.1:0",
	Proto: agd.ProtoDoT,
}

func TestLimiter(t *testing.T) {
	l := connlimiter.New(&connlimiter.Config{
		Metrics: connlimiter.EmptyMetrics{},
		Logger:  slogutil.NewDiscardLogger(),
		Stop:    1,
		Resume:  1,
	})

	// TODO(a.garipov):  Add fakenet.NewConn to golibs.
	conn := &fakenet.Conn{
		OnClose:     func() (err error) { return nil },
		OnLocalAddr: func() (laddr net.Addr) { panic(testutil.UnexpectedCall()) },
		OnRead:      func(b []byte) (n int, err error) { panic(testutil.UnexpectedCall(b)) },
		OnRemoteAddr: func() (addr net.Addr) {
			return &net.TCPAddr{
				IP:   netutil.IPv4Localhost().AsSlice(),
				Port: 1234,
			}
		},
		OnSetDeadline:      func(t time.Time) (err error) { panic(testutil.UnexpectedCall(t)) },
		OnSetReadDeadline:  func(t time.Time) (err error) { panic(testutil.UnexpectedCall(t)) },
		OnSetWriteDeadline: func(t time.Time) (err error) { panic(testutil.UnexpectedCall(t)) },
		OnWrite:            func(b []byte) (n int, err error) { panic(testutil.UnexpectedCall(b)) },
	}

	lsnr := &fakenet.Listener{
		OnAccept: func() (c net.Conn, err error) { return conn, nil },
		OnAddr: func() (addr net.Addr) {
			return &net.TCPAddr{
				IP:   netutil.IPv4Localhost().AsSlice(),
				Port: 853,
			}
		},
		OnClose: func() (err error) { return nil },
	}

	limited := l.Limit(lsnr, testServerInfo)

	// Accept one connection.
	gotConn, err := limited.Accept()
	require.NoError(t, err)

	// Try accepting another connection.  This should block until gotConn is
	// closed.
	otherStarted, otherListened := make(chan struct{}, 1), make(chan struct{}, 1)
	go func() {
		pt := &testutil.PanicT{}

		otherStarted <- struct{}{}

		otherConn, otherErr := limited.Accept()
		require.NoError(pt, otherErr)

		otherListened <- struct{}{}

		require.NoError(pt, otherConn.Close())
	}()

	// Wait for the other goroutine to start.
	testutil.RequireReceive(t, otherStarted, testTimeout)

	// Assert that the other connection hasn't been accepted.
	var otherAccepted bool
	select {
	case <-otherListened:
		otherAccepted = true
	default:
		otherAccepted = false
	}
	assert.False(t, otherAccepted)

	require.NoError(t, gotConn.Close())

	// Check that double close causes an error.
	assert.ErrorIs(t, gotConn.Close(), net.ErrClosed)

	testutil.RequireReceive(t, otherListened, testTimeout)

	err = limited.Close()
	require.NoError(t, err)

	// Check that double close causes an error.
	assert.ErrorIs(t, limited.Close(), net.ErrClosed)
}
