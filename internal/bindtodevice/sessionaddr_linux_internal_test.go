//go:build linux

package bindtodevice

import (
	"net"
	"testing"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/stretchr/testify/assert"
)

func TestSessionAddr_AddrPort(t *testing.T) {
	var a net.Addr = &sessionAddr{
		session: &packetSession{
			raddr: testRAddr,
		},
	}

	ap := netutil.NetAddrToAddrPort(a)

	assert.Equal(t, testRAddr.AddrPort(), ap)
}
