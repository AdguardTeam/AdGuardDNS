package bindtodevice

import "github.com/AdguardTeam/AdGuardDNS/internal/agd"

// ManagerConfig is the configuration structure for [NewManager].  All fields
// must be set.
type ManagerConfig struct {
	// ErrColl is the error collector that is used to collect non-critical
	// errors.
	ErrColl agd.ErrorCollector

	// ChannelBufferSize is the size of the buffers of the channels used to
	// dispatch TCP connections and UDP sessions.
	ChannelBufferSize int
}
