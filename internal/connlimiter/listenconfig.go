package connlimiter

import (
	"context"
	"net"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
)

// type check
var _ netext.ListenConfig = (*ListenConfig)(nil)

// ListenConfig is a [netext.ListenConfig] that uses a [*Limiter] to limit the
// number of active stream-connections.
type ListenConfig struct {
	listenConfig netext.ListenConfig
	limiter      *Limiter
	addr         string
}

// NewListenConfig returns a new netext.ListenConfig that uses l to limit the
// number of active stream-connections.  addr is used for metrics and logging.
// c and l must not be nil.
func NewListenConfig(c netext.ListenConfig, l *Limiter, addr string) (limited *ListenConfig) {
	return &ListenConfig{
		listenConfig: c,
		limiter:      l,
		addr:         addr,
	}
}

// ListenPacket implements the [netext.ListenConfig] interface for
// *ListenConfig.
func (c *ListenConfig) ListenPacket(
	ctx context.Context,
	network string,
	address string,
) (conn net.PacketConn, err error) {
	return c.listenConfig.ListenPacket(ctx, network, address)
}

// Listen implements the [netext.ListenConfig] interface for *ListenConfig.
// Listen returns a net.Listener wrapped by c's limiter.
func (c *ListenConfig) Listen(
	ctx context.Context,
	network string,
	address string,
) (l net.Listener, err error) {
	l, err = c.listenConfig.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}

	return c.limiter.Limit(l, &ConnMetricsData{
		// Use the configured address, which may differ from the one passed to
		// this method, to keep label values stable.
		Addr: c.addr,
	}), nil
}
