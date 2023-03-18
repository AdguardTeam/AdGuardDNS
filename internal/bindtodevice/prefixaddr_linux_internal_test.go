//go:build linux

package bindtodevice

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrefixAddr(t *testing.T) {
	const (
		wantStr = "1.2.3.0:56789/24"
		network = "tcp"
	)

	pa := &prefixNetAddr{
		prefix:  netip.MustParsePrefix("1.2.3.0/24"),
		network: network,
		port:    56789,
	}

	assert.Equal(t, wantStr, pa.String())
	assert.Equal(t, network, pa.Network())
}
