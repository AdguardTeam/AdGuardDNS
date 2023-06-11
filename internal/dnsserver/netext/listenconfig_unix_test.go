//go:build unix

package netext_test

import (
	"context"
	"syscall"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestDefaultListenConfigWithOOB(t *testing.T) {
	lc := netext.DefaultListenConfigWithOOB(nil)
	require.NotNil(t, lc)

	type syscallConner interface {
		SyscallConn() (c syscall.RawConn, err error)
	}

	t.Run("ipv4", func(t *testing.T) {
		c, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Implements(t, (*syscallConner)(nil), c)

		sc, err := c.(syscallConner).SyscallConn()
		require.NoError(t, err)

		err = sc.Control(func(fd uintptr) {
			val, opErr := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT)
			require.NoError(t, opErr)

			// TODO(a.garipov): Rewrite this to use actual expected values for
			// each OS.
			assert.NotEqual(t, 0, val)
		})
		require.NoError(t, err)
	})

	t.Run("ipv6", func(t *testing.T) {
		c, err := lc.ListenPacket(context.Background(), "udp6", "[::1]:0")
		if errors.Is(err, syscall.EADDRNOTAVAIL) {
			// Some CI machines have IPv6 disabled.
			t.Skipf("ipv6 seems to not be supported: %s", err)
		}

		require.NoError(t, err)
		require.NotNil(t, c)
		require.Implements(t, (*syscallConner)(nil), c)

		sc, err := c.(syscallConner).SyscallConn()
		require.NoError(t, err)

		err = sc.Control(func(fd uintptr) {
			val, opErr := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT)
			require.NoError(t, opErr)

			assert.NotEqual(t, 0, val)
		})
		require.NoError(t, err)
	})
}

func TestDefaultListenConfigWithSO(t *testing.T) {
	const (
		sndBufSize = 10000
		rcvBufSize = 20000
	)

	lc := netext.DefaultListenConfigWithOOB(&netext.ControlConfig{
		SndBufSize: sndBufSize,
		RcvBufSize: rcvBufSize,
	})
	require.NotNil(t, lc)

	type syscallConner interface {
		SyscallConn() (c syscall.RawConn, err error)
	}

	t.Run("ipv4", func(t *testing.T) {
		c, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Implements(t, (*syscallConner)(nil), c)

		sc, err := c.(syscallConner).SyscallConn()
		require.NoError(t, err)

		err = sc.Control(func(fd uintptr) {
			val, opErr := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
			require.NoError(t, opErr)

			// TODO(a.garipov): Rewrite this to use actual expected values for
			// each OS.
			assert.LessOrEqual(t, sndBufSize, val)
		})
		require.NoError(t, err)

		err = sc.Control(func(fd uintptr) {
			val, opErr := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
			require.NoError(t, opErr)

			assert.LessOrEqual(t, rcvBufSize, val)
		})
		require.NoError(t, err)
	})

	t.Run("ipv6", func(t *testing.T) {
		c, err := lc.ListenPacket(context.Background(), "udp6", "[::1]:0")
		if errors.Is(err, syscall.EADDRNOTAVAIL) {
			// Some CI machines have IPv6 disabled.
			t.Skipf("ipv6 seems to not be supported: %s", err)
		}

		require.NoError(t, err)
		require.NotNil(t, c)
		require.Implements(t, (*syscallConner)(nil), c)

		sc, err := c.(syscallConner).SyscallConn()
		require.NoError(t, err)

		err = sc.Control(func(fd uintptr) {
			val, opErr := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
			require.NoError(t, opErr)

			// TODO(a.garipov): Rewrite this to use actual expected values for
			// each OS.
			assert.LessOrEqual(t, sndBufSize, val)
		})
		require.NoError(t, err)

		err = sc.Control(func(fd uintptr) {
			val, opErr := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
			require.NoError(t, opErr)

			assert.LessOrEqual(t, rcvBufSize, val)
		})
		require.NoError(t, err)
	})
}
