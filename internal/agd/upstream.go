package agd

import (
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
)

// Upstream

// Upstream module configuration.
type Upstream struct {
	// Server is the upstream server we're using to forward DNS queries.
	Server netip.AddrPort

	// Network is the Server network protocol.
	Network forward.Network

	// FallbackServers is a list of the DNS servers we're using to fallback to
	// when the upstream server fails to respond.
	FallbackServers []netip.AddrPort

	// Timeout is the timeout for all outgoing DNS requests.
	Timeout time.Duration
}
