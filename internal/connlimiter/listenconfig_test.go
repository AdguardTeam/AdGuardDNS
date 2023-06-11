package connlimiter_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/connlimiter"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListenConfig(t *testing.T) {
	pc := &agdtest.PacketConn{
		OnClose:            func() (err error) { panic("not implemented") },
		OnLocalAddr:        func() (laddr net.Addr) { panic("not implemented") },
		OnReadFrom:         func(b []byte) (n int, addr net.Addr, err error) { panic("not implemented") },
		OnSetDeadline:      func(t time.Time) (err error) { panic("not implemented") },
		OnSetReadDeadline:  func(t time.Time) (err error) { panic("not implemented") },
		OnSetWriteDeadline: func(t time.Time) (err error) { panic("not implemented") },
		OnWriteTo:          func(b []byte, addr net.Addr) (n int, err error) { panic("not implemented") },
	}

	lsnr := &agdtest.Listener{
		OnAccept: func() (c net.Conn, err error) { panic("not implemented") },
		OnAddr:   func() (addr net.Addr) { panic("not implemented") },
		OnClose:  func() (err error) { return nil },
	}

	c := &agdtest.ListenConfig{
		OnListen: func(
			ctx context.Context,
			network string,
			address string,
		) (l net.Listener, err error) {
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
