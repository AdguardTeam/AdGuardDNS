package geoip

import "context"

// Metrics is an interface that is used for the collection of the GeoIP database
// statistics.
type Metrics interface {
	// HandleASNUpdateStatus updates the GeoIP ASN database update status.
	HandleASNUpdateStatus(ctx context.Context, err error)

	// HandleCountryUpdateStatus updates the GeoIP countries database update
	// status.
	HandleCountryUpdateStatus(ctx context.Context, err error)

	// IncrementHostCacheLookups increments the number of GeoIP cache lookups
	// for hostnames.
	IncrementHostCacheLookups(ctx context.Context, hit bool)

	// IncrementIPCacheLookups increments the number of GeoIP cache lookups for
	// IP addresses.
	IncrementIPCacheLookups(ctx context.Context, hit bool)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// HandleASNUpdateStatus implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) HandleASNUpdateStatus(_ context.Context, _ error) {}

// HandleCountryUpdateStatus implements the [Metrics] interface for
// EmptyMetrics.
func (EmptyMetrics) HandleCountryUpdateStatus(_ context.Context, _ error) {}

// IncrementHostCacheLookups implements the [Metrics] interface for
// EmptyMetrics.
func (EmptyMetrics) IncrementHostCacheLookups(_ context.Context, _ bool) {}

// IncrementIPCacheLookups implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) IncrementIPCacheLookups(_ context.Context, _ bool) {}
