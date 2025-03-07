package cmd

import (
	"math"

	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
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
var _ validate.Interface = (*network)(nil)

// Validate implements the [validate.Interface] interface for *network.
func (n *network) Validate() (err error) {
	if n == nil {
		return errors.ErrNoValue
	}

	const maxBufSize datasize.ByteSize = math.MaxInt32

	return errors.Join(
		validate.NoGreaterThan("so_sndbuf", n.SndBufSize, maxBufSize),
		validate.NoGreaterThan("so_rcvbuf", n.RcvBufSize, maxBufSize),
	)
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
