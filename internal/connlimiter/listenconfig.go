package connlimiter

import (
	"context"
	"net"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
)

// type check
var _ netext.ListenConfig = (*ListenConfig)(nil)

// ListenConfig is a [netext.ListenConfig] that uses a [*Limiter] to limit the
// number of active stream-connections.
type ListenConfig struct {
	listenConfig netext.ListenConfig
	limiter      *Limiter
}

// NewListenConfig returns a new netext.ListenConfig that uses l to limit the
// number of active stream-connections.
func NewListenConfig(c netext.ListenConfig, l *Limiter) (limited *ListenConfig) {
	return &ListenConfig{
		listenConfig: c,
		limiter:      l,
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
// Listen returns a net.Listener wrapped by c's limiter.  ctx must contain a
// [dnsserver.ServerInfo].
func (c *ListenConfig) Listen(
	ctx context.Context,
	network string,
	address string,
) (l net.Listener, err error) {
	l, err = c.listenConfig.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}

	return c.limiter.Limit(l, dnsserver.MustServerInfoFromContext(ctx)), nil
}
