//go:build linux

package bindtodevice

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// newTestChanListener is a helper for creating a *chanListener for tests.
func newTestChanListener(tb testing.TB, conns chan net.Conn) (l *chanListener) {
	tb.Helper()

	l = newChanListener(EmptyMetrics{}, conns, testSubnetIPv4, testLAddr)
	require.NotNil(tb, l)

	return l
}

// newTestChanPacketConn is a helper for creating a *chanPacketConn for tests.
func newTestChanPacketConn(
	tb testing.TB,
	sessions chan *packetSession,
	writeReqs chan *packetConnWriteReq,
) (c *chanPacketConn) {
	tb.Helper()

	c = newChanPacketConn(
		EmptyMetrics{},
		sessions,
		testSubnetIPv4,
		writeReqs,
		"",
		testLAddr,
	)
	require.NotNil(tb, c)

	return c
}
