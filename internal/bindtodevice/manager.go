package bindtodevice

import "github.com/AdguardTeam/AdGuardDNS/internal/errcoll"

// ManagerConfig is the configuration structure for [NewManager].  All fields
// must be set.
type ManagerConfig struct {
	// InterfaceStorage is used to get the information about the system's
	// network interfaces.  Normally, this is [DefaultInterfaceStorage].
	InterfaceStorage InterfaceStorage

	// ErrColl is the error collector that is used to collect non-critical
	// errors.
	ErrColl errcoll.Interface

	// ChannelBufferSize is the size of the buffers of the channels used to
	// dispatch TCP connections and UDP sessions.
	ChannelBufferSize int
}

// ControlConfig is the configuration of socket options.
type ControlConfig struct {
	// RcvBufSize defines the size of socket receive buffer in bytes.  Default
	// is zero (uses system settings).
	RcvBufSize int

	// SndBufSize defines the size of socket send buffer in bytes.  Default is
	// zero (uses system settings).
	SndBufSize int
}
