package tlsconfig

import (
	"context"
	"crypto/tls"
	"time"
)

// Metrics is an interface that is used for the collection of the TLS related
// statistics.
type Metrics interface {
	// BeforeHandshake returns a function that needs to be passed to
	// [tls.Config.GetConfigForClient].  f must not be nil.
	BeforeHandshake(proto string) (f func(*tls.ClientHelloInfo) (c *tls.Config, err error))

	// AfterHandshake returns a function that needs to be passed to
	// [tls.Config.VerifyConnection].  f must not be nil.
	AfterHandshake(
		proto string,
		srvName string,
		devDomains []string,
		srvCerts []tls.Certificate,
	) (f func(s tls.ConnectionState) (err error))

	// RefreshMetrics gathers statistics during updates.
	//
	// TODO(s.chzhen):  Separate it.
	RefreshMetrics
}

// RefreshMetrics is an interface that is used to collect statistics during TLS
// certificate and TLS session ticket updates.
type RefreshMetrics interface {
	// SetCertificateInfo sets the TLS certificate information.
	SetCertificateInfo(ctx context.Context, algo, subj string, notAfter time.Time)

	// SetSessionTicketRotationStatus sets the TLS session ticket rotation
	// status.
	SetSessionTicketRotationStatus(ctx context.Context, enabled bool)
}

// EmptyMetrics is the implementation of the [Metrics] interface that does
// nothing.
type EmptyMetrics struct{}

// type check
var _ Metrics = EmptyMetrics{}

// BeforeHandshake implements the [Metrics] interface for EmptyMetrics by
// returning a function that does nothing.
func (EmptyMetrics) BeforeHandshake(
	_ string,
) (f func(info *tls.ClientHelloInfo) (c *tls.Config, err error)) {
	return func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		return nil, nil
	}
}

// AfterHandshake implements the [Metrics] interface for EmptyMetrics by
// returning a function that does nothing.
func (EmptyMetrics) AfterHandshake(
	_ string,
	_ string,
	_ []string,
	_ []tls.Certificate,
) (f func(s tls.ConnectionState) (err error)) {
	return func(tls.ConnectionState) error {
		return nil
	}
}

// SetCertificateInfo implements the [Metrics] interface for EmptyMetrics.
func (EmptyMetrics) SetCertificateInfo(_ context.Context, _, _ string, _ time.Time) {}

// SetSessionTicketRotationStatus implements the [Metrics] interface for
// EmptyMetrics.
func (EmptyMetrics) SetSessionTicketRotationStatus(_ context.Context, _ bool) {}

// EmptyRefreshMetrics is the implementation of the [RefreshMetrics] interface
// that does nothing.
type EmptyRefreshMetrics struct{}

// type check
var _ RefreshMetrics = EmptyRefreshMetrics{}

// SetCertificateInfo implements the [RefreshMetrics] interface for
// EmptyRefreshMetrics.
func (EmptyRefreshMetrics) SetCertificateInfo(_ context.Context, _, _ string, _ time.Time) {}

// SetSessionTicketRotationStatus implements the [RefreshMetrics] interface for
// EmptyRefreshMetrics.
func (EmptyRefreshMetrics) SetSessionTicketRotationStatus(_ context.Context, _ bool) {}
