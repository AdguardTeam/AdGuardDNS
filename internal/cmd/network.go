package cmd

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
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

// validate returns an error if the network configuration is invalid.
func (n *network) validate() (err error) {
	if n == nil {
		return errNilConfig
	}

	return nil
}

// toInternal converts n to the bindtodevice control configuration and network
// extension control configuration.
func (n *network) toInternal() (bc *bindtodevice.ControlConfig, nc *netext.ControlConfig) {
	bc = &bindtodevice.ControlConfig{
		SndBufSize: int(n.SndBufSize.Bytes()),
		RcvBufSize: int(n.RcvBufSize.Bytes()),
	}
	nc = &netext.ControlConfig{
		SndBufSize: int(n.SndBufSize.Bytes()),
		RcvBufSize: int(n.RcvBufSize.Bytes()),
	}

	return bc, nc
}
