package forward

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

// MetricsListener is an interface that is used for monitoring the
// forward.Handler state.  The handler user may opt to supply a metrics
// interface implementation that would increment different kinds of metrics
// (for instance, prometheus metrics).
type MetricsListener interface {
	// OnForwardRequest is called when an upstream has finished processing a
	// request.
	// ctx is the context that has been passed to the handler's ServeDNS
	// function, ups is the Upstream that has been used for that, req and resp
	// are the DNS query and response (response can be nil), startTime is the
	// time when the upstream started processing the request, err is the
	// error if it happened.
	OnForwardRequest(
		ctx context.Context,
		ups Upstream,
		req, resp *dns.Msg,
		startTime time.Time,
		err error,
	)

	// OnUpstreamStatusChanged is called when an upstream status is changed
	// after a healthcheck probe.  True means the upstream is up, and false
	// means the upstream is backed off.
	OnUpstreamStatusChanged(ups Upstream, isMain, status bool)
}

// EmptyMetricsListener implements MetricsListener with empty functions.
// This implementation is used by default if the user does not supply a custom
// one.
type EmptyMetricsListener struct{}

// OnForwardRequest implements the MetricsListener interface for
// *EmptyMetricsListener.
func (e *EmptyMetricsListener) OnForwardRequest(
	_ context.Context,
	_ Upstream,
	_, _ *dns.Msg,
	_ time.Time,
	_ error,
) {
	// do nothing
}

// OnUpstreamStatusChanged implements the MetricsListener interface for
// *EmptyMetricsListener.
func (e *EmptyMetricsListener) OnUpstreamStatusChanged(_ Upstream, _, _ bool) {
	// do nothing
}

// type check
var _ MetricsListener = (*EmptyMetricsListener)(nil)
