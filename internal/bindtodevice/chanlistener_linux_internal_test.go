//go:build linux

package bindtodevice

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChanListener_Accept(t *testing.T) {
	conns := make(chan net.Conn, 1)
	l := newTestChanListener(t, conns)

	// A simple way to have a distinct net.Conn without actually implementing
	// the entire interface.
	c := struct {
		net.Conn
		Value int
	}{
		Value: 1,
	}

	conns <- c

	got, err := l.Accept()
	require.NoError(t, err)

	assert.Equal(t, c, got)
}

func TestChanListener_Addr(t *testing.T) {
	l := newTestChanListener(t, nil)
	got := l.Addr()
	assert.Equal(t, testLAddr, got)
}

func TestChanListener_Close(t *testing.T) {
	conns := make(chan net.Conn)
	l := newTestChanListener(t, conns)
	err := l.Close()
	assert.NoError(t, err)

	err = l.Close()
	assert.Error(t, err)
}
