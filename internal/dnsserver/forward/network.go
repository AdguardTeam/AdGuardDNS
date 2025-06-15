package forward

import (
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
)

// Network is an enumeration of networks [UpstreamPlain] supports.
type Network string

const (
	// NetworkAny means that [UpstreamPlain] will use the regular way of sending
	// a DNS query. First, it will send it over UDP. If for the response will
	// be truncated, it will automatically switch to using TCP.
	NetworkAny Network = ""

	// NetworkUDP means that [UpstreamPlain] will only use UDP.
	NetworkUDP Network = "udp"

	// NetworkTCP means that [UpstreamPlain] will only use TCP.
	NetworkTCP Network = "tcp"
)

// NewNetwork parses the string and returns the corresponding Network value.
func NewNetwork(networkStr string) (network Network, err error) {
	switch network = Network(networkStr); network {
	case NetworkAny, NetworkUDP, NetworkTCP:
		return network, nil
	default:
		return "", fmt.Errorf("networkStr: %w: %q", errors.ErrBadEnumValue, networkStr)
	}
}
