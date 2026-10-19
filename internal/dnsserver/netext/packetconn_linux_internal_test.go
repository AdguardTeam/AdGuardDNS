//go:build linux

package netext

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestIPDstOOBSize(t *testing.T) {
	// See https://github.com/miekg/dns/blob/v1.1.72/udp.go.
	len4 := len(ipv4.NewControlMessage(ipv4.FlagDst | ipv4.FlagInterface))
	len6 := len(ipv6.NewControlMessage(ipv6.FlagDst | ipv6.FlagInterface))

	assert.Equal(t, max(len4, len6), IPDstOOBSize)
}
