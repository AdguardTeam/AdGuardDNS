package tlsconfig

import (
	"context"
)

// CustomDomainStorage retrieves certificate data for a custom domain by the
// certificate name.
type CustomDomainStorage interface {
	// CertificateData returns the certificate data for the name.  If err is
	// nil, cert and key must not be nil.
	CertificateData(ctx context.Context, name string) (cert, key []byte, err error)
}

// EmptyCustomDomainStorage is the implementation of the [CustomDomainStorage]
// interface that does nothing.
type EmptyCustomDomainStorage struct{}

// type check
var _ CustomDomainStorage = EmptyCustomDomainStorage{}

// CertificateData implements the [CustomDomainStorage] interface for
// EmptyCustomDomainStorage
func (EmptyCustomDomainStorage) CertificateData(
	_ context.Context,
	_ string,
) (_, _ []byte, _ error) {
	return nil, nil, nil
}
