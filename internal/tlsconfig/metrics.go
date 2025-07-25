package tlsconfig

import (
	"context"
	"crypto/tls"
	"time"
)

// ManagerMetrics is an interface that is used for the collection of the
// TLS-related statistics.
type ManagerMetrics interface {
	// BeforeHandshake returns a function that needs to be passed to
	// [tls.Config.GetConfigForClient].  f must not be nil.
	BeforeHandshake(proto string) (f func(*tls.ClientHelloInfo) (c *tls.Config, err error))

	// AfterHandshake returns a function that needs to be passed to
	// [tls.Config.VerifyConnection].  f must not be nil.
	AfterHandshake(
		proto string,
		srvName string,
		devDomains []string,
		srvCerts []*tls.Certificate,
	) (f func(s tls.ConnectionState) (err error))

	// SetCertificateInfo sets the TLS certificate information.
	SetCertificateInfo(ctx context.Context, algo, subj string, notAfter time.Time)

	// SetSessionTicketRotationStatus sets the TLS session ticket rotation
	// status.
	SetSessionTicketRotationStatus(ctx context.Context, err error)
}

// EmptyManagerMetrics is the implementation of the [ManagerMetrics] interface
// that does nothing.
type EmptyManagerMetrics struct{}

// type check
var _ ManagerMetrics = EmptyManagerMetrics{}

// BeforeHandshake implements the [ManagerMetrics] interface for
// EmptyManagerMetrics by returning a function that does nothing.
func (EmptyManagerMetrics) BeforeHandshake(
	_ string,
) (f func(info *tls.ClientHelloInfo) (c *tls.Config, err error)) {
	return func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		return nil, nil
	}
}

// AfterHandshake implements the [ManagerMetrics] interface for
// EmptyManagerMetrics by returning a function that does nothing.
func (EmptyManagerMetrics) AfterHandshake(
	_ string,
	_ string,
	_ []string,
	_ []*tls.Certificate,
) (f func(s tls.ConnectionState) (err error)) {
	return func(tls.ConnectionState) error {
		return nil
	}
}

// SetCertificateInfo implements the [ManagerMetrics] interface for
// EmptyManagerMetrics.
func (EmptyManagerMetrics) SetCertificateInfo(_ context.Context, _, _ string, _ time.Time) {}

// SetSessionTicketRotationStatus implements the [ManagerMetrics] interface for
// EmptyManagerMetrics.
func (EmptyManagerMetrics) SetSessionTicketRotationStatus(_ context.Context, _ error) {}

// CustomDomainDBMetrics is an interface that is used for the collection of the
// statistics of the custom-domain database.
type CustomDomainDBMetrics interface {
	// ObserveOperation updates the statistics for an operation.  op must be one
	// of the following:
	//   - [CustomDomainDBMetricsOpAddCertificate]
	//   - [CustomDomainDBMetricsOpMatch]
	// dur must be positive.
	//
	// TODO(a.garipov):  Consider observing other operations as well.
	ObserveOperation(ctx context.Context, op string, dur time.Duration)

	// SetCurrentCustomDomainsCount updates the count of current domains.
	SetCurrentCustomDomainsCount(ctx context.Context, count uint)

	// SetWellKnownPathsCount updates the count of well-known paths for
	// certificate validation.
	SetWellKnownPathsCount(ctx context.Context, count uint)
}

// Operations for [CustomDomainDBMetrics].
const (
	CustomDomainDBMetricsOpAddCertificate = "add_certificate"
	CustomDomainDBMetricsOpMatch          = "match"
)

// EmptyCustomDomainDBMetrics is an implementation of the
// [CustomDomainDBMetrics] interface that does nothing.
type EmptyCustomDomainDBMetrics struct{}

// type check
var _ CustomDomainDBMetrics = EmptyCustomDomainDBMetrics{}

// ObserveOperation implements the [CustomDomainDBMetrics] interface for
// EmptyCustomDomainDBMetrics.
func (EmptyCustomDomainDBMetrics) ObserveOperation(_ context.Context, _ string, _ time.Duration) {}

// SetCurrentCustomDomainsCount implements the [CustomDomainDBMetrics] interface
// for EmptyCustomDomainDBMetrics.
func (EmptyCustomDomainDBMetrics) SetCurrentCustomDomainsCount(_ context.Context, _ uint) {}

// SetWellKnownPathsCount implements the [CustomDomainDBMetrics] interface
// for EmptyCustomDomainDBMetrics.
func (EmptyCustomDomainDBMetrics) SetWellKnownPathsCount(_ context.Context, _ uint) {}
