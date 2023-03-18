//go:build linux

package bindtodevice

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChanListenConfig(t *testing.T) {
	pc := newChanPacketConn(nil, nil, testLAddr)
	lsnr := newChanListener(nil, testLAddr)
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
