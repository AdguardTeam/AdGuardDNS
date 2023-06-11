//go:build linux

package bindtodevice

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChanListenConfig(t *testing.T) {
	pc := newChanPacketConn(nil, testSubnetIPv4, nil, testLAddr)
	lsnr := newChanListener(nil, testSubnetIPv4, testLAddr)
	c := chanListenConfig{
		packetConn: pc,
		listener:   lsnr,
	}

	ctx := context.Background()

	gotPC, err := c.ListenPacket(ctx, "", "")
	require.NoError(t, err)

	assert.Equal(t, pc, gotPC)

	gotLsnr, err := c.Listen(ctx, "", "")
	require.NoError(t, err)

	assert.Equal(t, lsnr, gotLsnr)
}
