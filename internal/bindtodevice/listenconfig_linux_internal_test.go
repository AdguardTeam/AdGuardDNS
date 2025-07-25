//go:build linux

package bindtodevice

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListenConfig(t *testing.T) {
	pc := newTestChanPacketConn(t, nil, nil)
	lsnr := newTestChanListener(t, nil)
	addr := &agdnet.PrefixNetAddr{
		Prefix: testSubnetIPv4,
		Net:    "",
		Port:   1234,
	}
	c := &ListenConfig{
		packetConn: pc,
		listener:   lsnr,
		addr:       addr,
	}

	ctx := context.Background()

	gotPC, err := c.ListenPacket(ctx, "", "")
	require.NoError(t, err)

	assert.Equal(t, pc, gotPC)

	gotLsnr, err := c.Listen(ctx, "", "")
	require.NoError(t, err)

	assert.Equal(t, lsnr, gotLsnr)

	gotAddr := c.Addr()
	assert.Equal(t, addr, gotAddr)
}
