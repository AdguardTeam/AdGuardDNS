package devicefinder

import "context"

// Metrics is an interface for collection of the statistics of the default
// device finder.
type Metrics interface {
	// IncrementCustomDomainMismatches is called when a detected device does not
	// belong to the profile which the custom domain belongs to.
	IncrementCustomDomainMismatches(ctx context.Context, domain string)

	// IncrementCustomDomainRequests is called when a request is recognized as
	// being to a custom domain belonging to a profile.
	IncrementCustomDomainRequests(ctx context.Context, domain string)

	// IncrementDoHAuthenticationFails is called when a request fails DoH
	// authentication.
	IncrementDoHAuthenticationFails(ctx context.Context)

	// IncrementUnknownDedicated is called when the DNS request is sent to an
	// unknown local address.
	IncrementUnknownDedicated(ctx context.Context)
}

// EmptyMetrics is an empty [Metrics] implementation that does nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// IncrementCustomDomainRequests implements the [Metrics] interface for
// EmptyMetrics.
func (EmptyMetrics) IncrementCustomDomainRequests(_ context.Context, _ string) {}

// IncrementCustomDomainMismatches implements the [Metrics] interface for
// EmptyMetrics.
func (EmptyMetrics) IncrementCustomDomainMismatches(_ context.Context, _ string) {}

// IncrementDoHAuthenticationFails implements the [Metrics] interface for
// EmptyMetrics.
func (EmptyMetrics) IncrementDoHAuthenticationFails(_ context.Context) {}

// IncrementUnknownDedicated implements the [Metrics] interface for
// EmptyMetrics.
func (EmptyMetrics) IncrementUnknownDedicated(_ context.Context) {}
