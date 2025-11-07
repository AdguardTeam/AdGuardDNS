package tlsconfig

import (
	"crypto/tls"
	"fmt"
	"net/netip"
	"slices"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
)

// certData is an internal representation of a certificate and its paths.
type certData struct {
	cert *tls.Certificate

	certPath string
	keyPath  string

	// TODO(a.garipov, e.burkov):  Think of a better approach to distinguish
	// between default and custom certificates.
	isCustom bool
}

// bindData is a helper type to map IP prefixes to certificate names.
//
// TODO(e.burkov):  Implement prefix comparison and use binary search.
type bindData struct {
	pref netip.Prefix
	name agd.CertificateName
}

// certIndex holds TLS certificates and their associated info.
type certIndex struct {
	// certs maps certificate names to their information.  Each entry
	// corresponds to a certificate name and its respective paths for the
	// certificate and key files.
	certs *sortedMap[agd.CertificateName, *certData]

	// bound are the IP prefixes for the certificates.  It must only contain
	// certificate names that are present in certs.
	bound []*bindData
}

// newCertIndex returns a new properly initialized [certIndex].
func newCertIndex() (s *certIndex) {
	return &certIndex{
		certs: newSortedMap[agd.CertificateName, *certData](),
	}
}

// add saves the TLS certificate's data under its name.  name must be unique,
// see [certIndex.contains].  certData must not be nil.
func (s *certIndex) add(name agd.CertificateName, certData *certData) {
	s.certs.set(name, certData)
}

// bind binds the certificate to the given prefix.  It returns false if the
// binding already exists.
func (s *certIndex) bind(name agd.CertificateName, pref netip.Prefix) (added bool) {
	if slices.ContainsFunc(s.bound, func(b *bindData) (found bool) {
		return b.name == name && b.pref == pref
	}) {
		return false
	}

	s.bound = append(s.bound, &bindData{
		pref: pref,
		name: name,
	})

	return true
}

// contains returns true if the TLS certificate has already been added using the
// provided name.
func (s *certIndex) contains(name agd.CertificateName) (ok bool) {
	_, ok = s.certs.get(name)

	return ok
}

// count returns the number of saved TLS certificates.
func (s *certIndex) count() (n int) {
	return s.certs.len()
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
	laddr := chi.Conn.LocalAddr()
	ip := netutil.NetAddrToAddrPort(laddr).Addr()
	if ip == (netip.Addr{}) {
		return nil, errors.Error("no local address")
	}

	// TODO(e.burkov):  Reuse the slice to decrease allocations.
	var errs []error
	for _, b := range s.bound {
		if !b.pref.Contains(ip) {
			continue
		}

		certData, ok := s.certs.get(b.name)
		if !ok {
			panic(fmt.Errorf("certificate %q: %w", b.name, errors.ErrNoValue))
		}

		cert = certData.cert
		err = chi.SupportsCertificate(cert)
		if err == nil {
			return cert, nil
		}

		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return nil, fmt.Errorf("no certificate found for %s", ip)
}

// rangeFn calls fn for each stored TLS certificate and its data.  fn must not
// be nil and must not modify certData.
func (s *certIndex) rangeFn(fn func(name agd.CertificateName, certData *certData) (cont bool)) {
	for name, cd := range s.certs.rangeFn {
		if !fn(name, cd) {
			return
		}
	}
}

// remove deletes the certificate from s by name.  name must be valid.
func (s *certIndex) remove(name agd.CertificateName) {
	s.certs.del(name)
	s.bound = slices.DeleteFunc(s.bound, func(b *bindData) (found bool) {
		return b.name == name
	})
}

// stored returns the saved TLS certificates.  certs' values must not be
// modified.
func (s *certIndex) stored() (certs []*tls.Certificate) {
	for _, cd := range s.certs.rangeFn {
		certs = append(certs, cd.cert)
	}

	return certs
}

// update updates the certificate corresponding to name.  It returns true if the
// certificate was updated.  name must be valid, c must not be nil.
func (s *certIndex) update(name agd.CertificateName, c *tls.Certificate) (ok bool) {
	certData, ok := s.certs.get(name)
	if ok {
		certData.cert = c
	}

	return ok
}
