package tlsconfig

import (
	"context"
	"crypto/tls"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
)

// AddParams are the parameters for [Manager.Add].
type AddParams struct {
	// Name is the name of the certificate to add.  It must be valid.
	Name agd.CertificateName

	// CertPath is the path to the certificate.  It must be a valid existing
	// filesystem path.
	CertPath string

	// KeyPath is the path to the key.  It must be a valid existing filesystem
	// path.
	KeyPath string

	// IsCustom defines if the certificate belongs to a custom domain.  If true,
	// the certificate's data should not be reported in metrics.
	IsCustom bool
}

// Manager stores and updates TLS configurations.
type Manager interface {
	// Add saves an initialized TLS certificate using the provided params.
	//
	// Add must ignore duplicates.
	Add(ctx context.Context, params *AddParams) (err error)

	// Bind binds the certificate to the given prefix.
	//
	// Bind must ignore duplicating name-prefix combinations.
	Bind(ctx context.Context, name agd.CertificateName, prefix netip.Prefix) (err error)

	// Clone returns the TLS configuration that contains saved TLS certificates.
	Clone() (c *tls.Config)

	// CloneWithMetrics is like [Manager.Clone] but it also sets metrics.
	CloneWithMetrics(proto, srvName string, deviceDomains []string) (c *tls.Config)

	// Remove deletes a custom certificate by its name.  name must be valid.
	Remove(ctx context.Context, name agd.CertificateName) (err error)
}

// EmptyManager is the implementation of the [Manager] interface that does
// nothing.
type EmptyManager struct{}

// type check
var _ Manager = EmptyManager{}

// Add implements the [Manager] interface for EmptyManager.
func (EmptyManager) Add(_ context.Context, _ *AddParams) (err error) { return nil }

// Bind implements the [Manager] interface for EmptyManager.
func (EmptyManager) Bind(_ context.Context, _ agd.CertificateName, _ netip.Prefix) (err error) {
	return nil
}

// Clone implements the [Manager] interface for EmptyManager.
func (EmptyManager) Clone() (c *tls.Config) { return nil }

// CloneWithMetrics implements the [Manager] interface for EmptyManager.
func (EmptyManager) CloneWithMetrics(_, _ string, _ []string) (c *tls.Config) { return nil }

// Remove implements the [Manager] interface for EmptyManager.
func (EmptyManager) Remove(_ context.Context, _ agd.CertificateName) (err error) { return nil }
