package tlsconfig

import (
	"crypto/tls"
	"slices"

	"github.com/AdguardTeam/golibs/errors"
)

// certPaths contains a certificate path and a key path.
type certPaths struct {
	certPath string
	keyPath  string
}

// certStorage holds TLS certificates and their associated file paths.  Each
// entry in the slices corresponds to a certificate and its respective paths for
// the certificate and key files.  Using this struct allows us to reduce
// allocations.
type certStorage struct {
	// certs contains the list of TLS certificates.  All elements must not be
	// nil.
	certs []*tls.Certificate

	// paths contains corresponding file paths for certificate and key files.
	// All elements must not be nil.
	paths []*certPaths
}

// add saves the TLS certificate and its paths.  Certificate paths must only be
// added once, see [certStorage.contains].  cert and cp must not be nil.
func (s *certStorage) add(cert *tls.Certificate, cp *certPaths) {
	s.certs = append(s.certs, cert)
	s.paths = append(s.paths, cp)
}

// contains returns true if the TLS certificate has already been added using the
// provided file paths.  cp must not be nil.
func (s *certStorage) contains(cp *certPaths) (ok bool) {
	return slices.ContainsFunc(s.paths, func(p *certPaths) (found bool) {
		return *cp == *p
	})
}

// count returns the number of saved TLS certificates.
func (s *certStorage) count() (n int) {
	return len(s.certs)
}

// certFor returns the TLS certificate for chi.  chi must not be nil.  cert must
// not be modified.
func (s *certStorage) certFor(chi *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
	var errs []error
	for _, c := range s.certs {
		err = chi.SupportsCertificate(c)
		if err == nil {
			return c, nil
		}

		errs = append(errs, err)
	}

	return nil, errors.Join(errs...)
}

// rangeFn calls fn for each stored TLS certificate and its paths.  fn must not
// be nil.  Neither cert nor cp must be modified.
func (s *certStorage) rangeFn(fn func(cert *tls.Certificate, cp *certPaths) (cont bool)) {
	for i, p := range s.paths {
		if !fn(s.certs[i], p) {
			return
		}
	}
}

// stored returns the list of saved TLS certificates.
func (s *certStorage) stored() (certs []*tls.Certificate) {
	return s.certs
}

// update updates the certificate corresponding to the paths.  cp and c must not
// be nil.
//
// TODO(a.garipov):  Think of a better way to do this that doesn't involve code
// that looks like iterator invalidation.
func (s *certStorage) update(cp *certPaths, c *tls.Certificate) (ok bool) {
	for i, p := range s.paths {
		if *cp == *p {
			s.certs[i] = c

			return true
		}
	}

	return false
}
