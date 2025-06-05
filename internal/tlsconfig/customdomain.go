package tlsconfig

import (
	"context"
)

// CustomDomainStorage retrieves certificate data for a custom domain by the
// certificate name.
//
// TODO(a.garipov):  Use.
type CustomDomainStorage interface {
	// CertificateData returns the certificate data for the name.  If err is
	// nil, cert and key must not be nil.
	CertificateData(ctx context.Context, name string) (cert, key []byte, err error)
}
