//go:build linux

package netext

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestUDPOOBSize(t *testing.T) {
	// See https://github.com/miekg/dns/blob/v1.1.50/udp.go.

	len4 := len(ipv4.NewControlMessage(ipv4.FlagDst | ipv4.FlagInterface))
	len6 := len(ipv6.NewControlMessage(ipv6.FlagDst | ipv6.FlagInterface))

	max := len4
	if len6 > max {
		max = len6
	}

	assert.Equal(t, max, IPDstOOBSize)
}
