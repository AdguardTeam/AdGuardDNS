package connlimiter_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/connlimiter"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/fakenet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListenConfig(t *testing.T) {
	// TODO(a.garipov):  Add fakenet.NewPacketConn to golibs.
	pc := &fakenet.PacketConn{
		OnClose:     func() (err error) { panic(testutil.UnexpectedCall()) },
		OnLocalAddr: func() (laddr net.Addr) { panic(testutil.UnexpectedCall()) },
		OnReadFrom: func(b []byte) (n int, addr net.Addr, err error) {
			panic(testutil.UnexpectedCall(b))
		},
		OnSetDeadline:      func(t time.Time) (err error) { panic(testutil.UnexpectedCall(t)) },
		OnSetReadDeadline:  func(t time.Time) (err error) { panic(testutil.UnexpectedCall(t)) },
		OnSetWriteDeadline: func(t time.Time) (err error) { panic(testutil.UnexpectedCall(t)) },
		OnWriteTo: func(b []byte, addr net.Addr) (n int, err error) {
			panic(testutil.UnexpectedCall(b, addr))
		},
	}

	lsnr := &fakenet.Listener{
		OnAccept: func() (c net.Conn, err error) { panic(testutil.UnexpectedCall()) },
		OnAddr:   func() (addr net.Addr) { panic(testutil.UnexpectedCall()) },
		OnClose:  func() (err error) { return nil },
	}

	c := &agdtest.ListenConfig{
		OnListen: func(ctx context.Context, network, address string) (l net.Listener, err error) {
			return lsnr, nil
		},
		OnListenPacket: func(
			ctx context.Context,
			network string,
			address string,
		) (conn net.PacketConn, err error) {
			return pc, nil
		},
	}

	l := connlimiter.New(&connlimiter.Config{
		Metrics: connlimiter.EmptyMetrics{},
		Logger:  slogutil.NewDiscardLogger(),
		Stop:    1,
		Resume:  1,
	})

	limited := connlimiter.NewListenConfig(c, l)

	ctx := dnsserver.ContextWithServerInfo(context.Background(), testServerInfo)
	gotLsnr, err := limited.Listen(ctx, "", "")
	require.NoError(t, err)

	// TODO(a.garipov): Add more testing logic here if [Limiter] becomes
	// unexported.
	assert.NotEqual(t, lsnr, gotLsnr)

	err = gotLsnr.Close()
	require.NoError(t, err)

	gotPC, err := limited.ListenPacket(ctx, "", "")
	require.NoError(t, err)

	// TODO(a.garipov): Add more testing logic here if [Limiter] becomes
	// unexported.
	assert.Equal(t, pc, gotPC)
}
