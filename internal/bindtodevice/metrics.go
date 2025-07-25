package bindtodevice

import (
	"context"
	"net/netip"
	"time"
)

// Metrics is an interface for collecting bindtodevice-related statistics.
type Metrics interface {
	// IncrementUnknownTCPRequests increments the counter for TCP requests to
	// unknown local address.
	IncrementUnknownTCPRequests(ctx context.Context)

	// IncrementUnknownUDPRequests increments the counter for UDP requests to
	// unknown local address.
	IncrementUnknownUDPRequests(ctx context.Context)

	// SetTCPConnsChanSize sets the current number of TCP connections in the
	// channel by subnet.
	SetTCPConnsChanSize(ctx context.Context, subnet netip.Prefix, n uint)

	// SetUDPConnsChanSize sets the current number of UDP connections in the
	// channel by subnet.
	SetUDPSessionsChanSize(ctx context.Context, subnet netip.Prefix, n uint)

	// SetUDPWriteRequestsChanSize sets the current number of UDP write requests
	// in the channel by interface name.
	SetUDPWriteRequestsChanSize(ctx context.Context, name string, n uint)

	// ObserveUDPWriteDuration observes the duration of a UDP write operation by
	// interface name.
	ObserveUDPWriteDuration(ctx context.Context, name string, dur time.Duration)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// IncrementUnknownTCPRequests implements the [Metrics] interface for
// EmptyMetrics.
func (EmptyMetrics) IncrementUnknownTCPRequests(_ context.Context) {}

// IncrementUnknownUDPRequests implements the [Metrics] interface for
// EmptyMetrics.
func (EmptyMetrics) IncrementUnknownUDPRequests(_ context.Context) {}

// SetTCPConnsChanSize implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) SetTCPConnsChanSize(_ context.Context, _ netip.Prefix, _ uint) {}

// SetUDPSessionsChanSize implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) SetUDPSessionsChanSize(_ context.Context, _ netip.Prefix, _ uint) {}

// SetUDPWriteRequestsChanSize implements the [Metrics] interface for
// EmptyMetrics.
func (EmptyMetrics) SetUDPWriteRequestsChanSize(_ context.Context, _ string, _ uint) {}

// ObserveUDPWriteDuration implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) ObserveUDPWriteDuration(_ context.Context, _ string, _ time.Duration) {}
