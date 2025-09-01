package access

import (
	"context"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/miekg/dns"
)

// Blocker is the interface to control DNS resolution access.
type Blocker interface {
	// IsBlocked returns true if the req should be blocked.  req must not be
	// nil, and req.Question must have one item.
	IsBlocked(
		ctx context.Context,
		req *dns.Msg,
		rAddr netip.AddrPort,
		l *geoip.Location,
	) (isBlocked bool)
}

// EmptyBlocker is an empty [Blocker] implementation that does nothing.
type EmptyBlocker struct{}

// type check
var _ Blocker = EmptyBlocker{}

// IsBlocked implements the [Blocker] interface for EmptyBlocker.  It always
// returns false.
func (EmptyBlocker) IsBlocked(
	_ context.Context,
	_ *dns.Msg,
	_ netip.AddrPort,
	_ *geoip.Location,
) (isBlocked bool) {
	return false
}
