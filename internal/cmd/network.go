package cmd

import (
	"fmt"
	"math"

	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/c2h5oh/datasize"
)

// network defines the network settings.
type network struct {
	// SndBufSize defines the size of socket send buffer.  Default is zero (uses
	// system settings).
	SndBufSize datasize.ByteSize `yaml:"so_sndbuf"`

	// RcvBufSize defines the size of socket receive buffer.  Default is zero
	// (uses system settings).
	RcvBufSize datasize.ByteSize `yaml:"so_rcvbuf"`
}

// type check
var _ validator = (*interfaceListener)(nil)

// validate implements the [validator] interface for *network.
func (n *network) validate() (err error) {
	const maxBufSize datasize.ByteSize = math.MaxInt32
	switch {
	case n == nil:
		return errors.ErrNoValue
	case n.SndBufSize > maxBufSize:
		return fmt.Errorf(
			"so_sndbuf: %s: must be less than or equal to %s",
			errors.ErrOutOfRange,
			maxBufSize,
		)
	case n.RcvBufSize > maxBufSize:
		return fmt.Errorf(
			"so_rcvbuf: %s: must be less than or equal to %s",
			errors.ErrOutOfRange,
			maxBufSize,
		)
	default:
		return nil
	}
}

// toInternal converts n to the bindtodevice control configuration and network
// extension control configuration.  n must be valid.
func (n *network) toInternal() (bc *bindtodevice.ControlConfig, nc *netext.ControlConfig) {
	bc = &bindtodevice.ControlConfig{
		// #nosec G115 -- Validated in [network.validate].
		SndBufSize: int(n.SndBufSize.Bytes()),
		// #nosec G115 -- Validated in [network.validate].
		RcvBufSize: int(n.RcvBufSize.Bytes()),
	}
	nc = &netext.ControlConfig{
		// #nosec G115 -- Validated in [network.validate].
		SndBufSize: int(n.SndBufSize.Bytes()),
		// #nosec G115 -- Validated in [network.validate].
		RcvBufSize: int(n.RcvBufSize.Bytes()),
	}

	return bc, nc
}
