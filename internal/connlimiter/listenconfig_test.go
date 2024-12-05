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
	"github.com/AdguardTeam/golibs/testutil/fakenet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListenConfig(t *testing.T) {
	pc := &fakenet.PacketConn{
		OnClose:     func() (_ error) { panic("not implemented") },
		OnLocalAddr: func() (_ net.Addr) { panic("not implemented") },
		OnReadFrom: func(_ []byte) (_ int, _ net.Addr, _ error) {
			panic("not implemented")
		},
		OnSetDeadline:      func(_ time.Time) (_ error) { panic("not implemented") },
		OnSetReadDeadline:  func(_ time.Time) (_ error) { panic("not implemented") },
		OnSetWriteDeadline: func(_ time.Time) (_ error) { panic("not implemented") },
		OnWriteTo: func(_ []byte, _ net.Addr) (_ int, _ error) {
			panic("not implemented")
		},
	}

	lsnr := &fakenet.Listener{
		OnAccept: func() (_ net.Conn, _ error) { panic("not implemented") },
		OnAddr:   func() (_ net.Addr) { panic("not implemented") },
		OnClose:  func() (_ error) { return nil },
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

	l, err := connlimiter.New(&connlimiter.Config{
		Logger: slogutil.NewDiscardLogger(),
		Stop:   1,
		Resume: 1,
	})
	require.NoError(t, err)

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
