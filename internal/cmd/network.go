package cmd

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
)

// network defines the network settings.
//
// TODO(a.garipov): Use [datasize.ByteSize] for sizes.
type network struct {
	// SndBufSize defines the size of socket send buffer in bytes.  Default is
	// zero (uses system settings).
	SndBufSize int `yaml:"so_sndbuf"`

	// RcvBufSize defines the size of socket receive buffer in bytes.  Default
	// is zero (uses system settings).
	RcvBufSize int `yaml:"so_rcvbuf"`
}

// validate returns an error if the network configuration is invalid.
func (n *network) validate() (err error) {
	if n == nil {
		return errNilConfig
	}

	if n.SndBufSize < 0 {
		return newMustBeNonNegativeError("so_sndbuf", n.SndBufSize)
	}

	if n.RcvBufSize < 0 {
		return newMustBeNonNegativeError("so_rcvbuf", n.RcvBufSize)
	}

	return nil
}

// toInternal converts n to the bindtodevice control configuration and network
// extension control configuration.
func (n *network) toInternal() (bc *bindtodevice.ControlConfig, nc *netext.ControlConfig) {
	bc = &bindtodevice.ControlConfig{
		SndBufSize: n.SndBufSize,
		RcvBufSize: n.RcvBufSize,
	}
	nc = &netext.ControlConfig{
		SndBufSize: n.SndBufSize,
		RcvBufSize: n.RcvBufSize,
	}

	return bc, nc
}
