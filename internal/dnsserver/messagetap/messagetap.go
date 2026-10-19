// Package messagetap contains the logic for tapping DNS messages.
package messagetap

import (
	"context"
	"net/netip"
	"time"
)

// Interface is the interface for tapping DNS messages.  It is used to intercept
// and inspect DNS request and response messages.
type Interface interface {
	// TapRequest intercepts and inspects a DNS request message.  laddr is the
	// local address, raddr is the remote address, now is the request time, and
	// req is the raw DNS request bytes.  It must be safe for concurrent use.
	TapRequest(ctx context.Context, now time.Time, laddr, raddr netip.AddrPort, req []byte)

	// TapResponse intercepts and inspects a DNS response message.  laddr is the
	// local address, raddr is the remote address, now is the response time, and
	// resp is the raw DNS response bytes.  It must be safe for concurrent use.
	TapResponse(ctx context.Context, now time.Time, laddr, raddr netip.AddrPort, resp []byte)
}

// Empty is an implementation of the [Interface] interface that does nothing.
type Empty struct{}

// type check
var _ Interface = Empty{}

// TapRequest implements the [Interface] interface for Empty.
func (Empty) TapRequest(_ context.Context, _ time.Time, _, _ netip.AddrPort, _ []byte) {}

// TapResponse implements the [Interface] interface for Empty.
func (Empty) TapResponse(_ context.Context, _ time.Time, _, _ netip.AddrPort, _ []byte) {}
