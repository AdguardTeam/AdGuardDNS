package pool_test

import (
	"context"
	"net"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/pool"
	"github.com/stretchr/testify/require"
)

func TestPool_Get(t *testing.T) {
	factory := pool.Factory(func(_ context.Context) (net.Conn, error) {
		return &net.TCPConn{}, nil
	})
	p := pool.NewPool(10, factory)

	conn1, err := p.Get(context.Background())
	require.NoError(t, err)
	require.NotNil(t, conn1)
}

func TestPool_Put(t *testing.T) {
	factory := pool.Factory(func(_ context.Context) (net.Conn, error) {
		return &net.TCPConn{}, nil
	})
	p := pool.NewPool(10, factory)

	conn1, err := p.Get(context.Background())
	require.NoError(t, err)
	require.NotNil(t, conn1)

	conn2, err := p.Get(context.Background())
	require.NoError(t, err)
	require.NotNil(t, conn2)
	require.NotEqual(t, conn1, conn2)

	err = p.Put(conn1)
	require.NoError(t, err)

	err = p.Put(conn2)
	require.NoError(t, err)

	newConn1, err := p.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, conn1, newConn1)

	newConn2, err := p.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, conn2, newConn2)
}

type testConn struct {
	net.Conn
	closed bool
}

func (c *testConn) Close() error {
	c.closed = true
	return nil
}

func TestPool_Close(t *testing.T) {
	factory := pool.Factory(func(_ context.Context) (net.Conn, error) {
		return &testConn{}, nil
	})
	p := pool.NewPool(10, factory)

	conn1, err := p.Get(context.Background())
	require.NoError(t, err)
	require.NotNil(t, conn1)

	conn2, err := p.Get(context.Background())
	require.NoError(t, err)
	require.NotNil(t, conn2)
	require.NotEqual(t, conn1, conn2)

	// Now put one connection back to the pool right away
	err = p.Put(conn1)
	require.NoError(t, err)

	// Close the pool
	err = p.Close()
	require.NoError(t, err)

	// Check that the first connection is now closed
	require.True(t, conn1.Conn.(*testConn).closed)

	// The second one is still alive
	require.False(t, conn2.Conn.(*testConn).closed)

	// Check that putting it back to the pull returns ErrClosed
	err = p.Put(conn2)
	require.ErrorIs(t, err, pool.ErrClosed)

	// The second connection must be closed now
	require.True(t, conn2.Conn.(*testConn).closed)

	// Check that Get now also returns ErrClosed
	c, err := p.Get(context.Background())
	require.ErrorIs(t, err, pool.ErrClosed)
	require.Nil(t, c)
}
