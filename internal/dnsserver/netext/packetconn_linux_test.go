//go:build linux

package netext_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO(a.garipov): Add IPv6 test.
func TestSessionPacketConn(t *testing.T) {
	const numTries = 5

	// Try the test multiple times to reduce flakiness due to UDP failures.
	var success4, success6 bool
	for i := 0; i < numTries; i++ {
		var isTimeout4, isTimeout6 bool
		success4 = t.Run(fmt.Sprintf("ipv4_%d", i), func(t *testing.T) {
			isTimeout4 = testSessionPacketConn(t, "udp4", "0.0.0.0:0", net.IP{127, 0, 0, 1})
		})

		success6 = t.Run(fmt.Sprintf("ipv6_%d", i), func(t *testing.T) {
			isTimeout6 = testSessionPacketConn(t, "udp6", "[::]:0", net.IPv6loopback)
		})

		if success4 && success6 {
			break
		} else if isTimeout4 || isTimeout6 {
			continue
		}

		t.Fail()
	}

	if !success4 {
		t.Errorf("ipv4 test failed after %d attempts", numTries)
	} else if !success6 {
		t.Errorf("ipv6 test failed after %d attempts", numTries)
	}
}

func testSessionPacketConn(t *testing.T, proto, addr string, dstIP net.IP) (isTimeout bool) {
	lc := netext.DefaultListenConfigWithOOB(nil)
	require.NotNil(t, lc)

	c, err := lc.ListenPacket(context.Background(), proto, addr)
	if isTimeoutOrFail(t, err) {
		return true
	}

	require.NotNil(t, c)

	deadline := time.Now().Add(1 * time.Second)
	err = c.SetDeadline(deadline)
	require.NoError(t, err)

	laddr := testutil.RequireTypeAssert[*net.UDPAddr](t, c.LocalAddr())
	require.NotNil(t, laddr)

	dstAddr := &net.UDPAddr{
		IP:   dstIP,
		Port: laddr.Port,
	}

	remoteConn, err := net.DialUDP(proto, nil, dstAddr)
	if proto == "udp6" && errors.Is(err, syscall.EADDRNOTAVAIL) {
		// Some CI machines have IPv6 disabled.
		t.Skipf("ipv6 seems to not be supported: %s", err)
	} else if isTimeoutOrFail(t, err) {
		return true
	}

	err = remoteConn.SetDeadline(deadline)
	require.NoError(t, err)

	msg := []byte("hello")
	msgLen := len(msg)
	_, err = remoteConn.Write(msg)
	if isTimeoutOrFail(t, err) {
		return true
	}

	require.Implements(t, (*netext.SessionPacketConn)(nil), c)

	buf := make([]byte, msgLen)
	n, sess, err := netext.ReadFromSession(c, buf)
	if isTimeoutOrFail(t, err) {
		return true
	}

	assert.Equal(t, msgLen, n)
	assert.Equal(t, net.Addr(dstAddr), sess.LocalAddr())
	assert.Equal(t, remoteConn.LocalAddr(), sess.RemoteAddr())
	assert.Equal(t, msg, buf)

	respMsg := []byte("world")
	respMsgLen := len(respMsg)
	n, err = netext.WriteToSession(c, respMsg, sess)
	if isTimeoutOrFail(t, err) {
		return true
	}

	assert.Equal(t, respMsgLen, n)

	buf = make([]byte, respMsgLen)
	n, err = remoteConn.Read(buf)
	if isTimeoutOrFail(t, err) {
		return true
	}

	assert.Equal(t, respMsgLen, n)
	assert.Equal(t, respMsg, buf)

	return false
}

// isTimeoutOrFail is a helper function that returns true if err is a timeout
// error and also calls require.NoError on err.
func isTimeoutOrFail(t *testing.T, err error) (ok bool) {
	t.Helper()

	if err == nil {
		return false
	}

	defer require.NoError(t, err)

	return errors.Is(err, os.ErrDeadlineExceeded)
}
