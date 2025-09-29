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
	// TODO(a.garipov, e.burkov):  Think of a better approach to distinct
	// between default and custom certificates.
	isCustom bool
}

// certIndex holds TLS certificates and their associated file paths.  Each entry
// in the slices corresponds to a certificate and its respective paths for the
// certificate and key files.  Using this struct allows us to reduce
// allocations.
type certIndex struct {
	// certs contains the list of TLS certificates.  All elements must not be
	// nil.
	certs []*tls.Certificate

	// paths contains corresponding file paths for certificate and key files.
	// All elements must not be nil.
	paths []*certPaths
}

// add saves the TLS certificate and its paths.  Certificate paths must only be
// added once, see [certStorage.contains].  cert and cp must not be nil.
func (s *certIndex) add(cert *tls.Certificate, cp *certPaths) {
	s.certs = append(s.certs, cert)
	s.paths = append(s.paths, cp)
}

// contains returns true if the TLS certificate has already been added using the
// provided file paths.  cp must not be nil.
func (s *certIndex) contains(cp *certPaths) (ok bool) {
	return slices.ContainsFunc(s.paths, func(p *certPaths) (found bool) {
		return *cp == *p
	})
}

// count returns the number of saved TLS certificates.
func (s *certIndex) count() (n int) {
	return len(s.certs)
}

// certFor returns the TLS certificate for chi.  chi must not be nil.  cert must
// not be modified.
//
// NOTE:  It returns the first certificate for a Client Hello message with no
// server name, for example when using IP-only certificates, so the IP cert must
// be the first one.
//
// TODO(a.garipov):  Explore the above situation and consider fixes to allow
// custom IP-only certs.
func (s *certIndex) certFor(chi *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
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
func (s *certIndex) rangeFn(fn func(cert *tls.Certificate, cp *certPaths) (cont bool)) {
	for i, p := range s.paths {
		if !fn(s.certs[i], p) {
			return
		}
	}
}

// remove deletes the certificate from s.  cp must not be nil.
func (s *certIndex) remove(cp *certPaths) {
	i := slices.IndexFunc(s.paths, func(p *certPaths) (found bool) {
		return *cp == *p
	})
	if i == -1 {
		return
	}

	s.certs = slices.Delete(s.certs, i, i+1)
	s.paths = slices.Delete(s.paths, i, i+1)
}

// stored returns the list of saved TLS certificates.
func (s *certIndex) stored() (certs []*tls.Certificate) {
	return s.certs
}

// update updates the certificate corresponding to the paths.  cp and c must not
// be nil.
//
// TODO(a.garipov):  Think of a better way to do this that doesn't involve code
// that looks like iterator invalidation.
func (s *certIndex) update(cp *certPaths, c *tls.Certificate) (ok bool) {
	for i, p := range s.paths {
		if *cp == *p {
			s.certs[i] = c

			return true
		}
	}

	return false
}
