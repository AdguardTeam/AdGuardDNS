package dnssvc

import (
	"context"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
)

// contextConstructor is a [dnsserver.ContextConstructor] implementation that
// returns a context with the given timeout as well as a new [agd.RequestID].
type contextConstructor struct {
	timeout time.Duration
}

// newContextConstructor returns a new properly initialized *contextConstructor.
func newContextConstructor(timeout time.Duration) (c *contextConstructor) {
	return &contextConstructor{
		timeout: timeout,
	}
}

// type check
var _ dnsserver.ContextConstructor = (*contextConstructor)(nil)

// New implements the [dnsserver.ContextConstructor] interface for
// *contextConstructor.  It returns a context with a new [agd.RequestID] as well
// as its timeout and the corresponding cancelation function.
func (c *contextConstructor) New() (ctx context.Context, cancel context.CancelFunc) {
	ctx, cancel = context.WithTimeout(context.Background(), c.timeout)
	ctx = agd.WithRequestID(ctx, agd.NewRequestID())

	return ctx, cancel
}
