package tlsconfig

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/optslog"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
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
	// logger is used to log debugging information.  It must not be nil.
	logger *slog.Logger

	// certs maps certificate names to their information.  Each entry
	// corresponds to a certificate name and its respective paths for the
	// certificate and key files.
	certs *sortedMap[agd.CertificateName, *certData]

	// errsPool is a pool of error slices to reduce allocations when collecting
	// errors.
	errsPool *syncutil.Pool[[]error]

	// bound are the IP prefixes for the certificates.  It must only contain
	// certificate names that are present in certs.
	bound []*bindData
}

// defaultErrSliceLen is the default size of the pooled error slice to be
// preallocated.
const defaultErrSliceLen = 16

// newCertIndex returns a new properly initialized [certIndex].  l must not be
// nil.
func newCertIndex(l *slog.Logger) (s *certIndex) {
	return &certIndex{
		logger:   l,
		certs:    newSortedMap[agd.CertificateName, *certData](),
		errsPool: syncutil.NewSlicePool[error](defaultErrSliceLen),
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
func (s *certIndex) certFor(chi *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
	laddr := laddrFromConn(chi.Conn)
	ip := netutil.NetAddrToAddrPort(laddr).Addr()
	if ip == (netip.Addr{}) {
		optslog.Debug2(
			chi.Context(),
			s.logger,
			"no ip in local addr",
			"laddr", laddr,
			"client_sni", chi.ServerName,
		)

		return nil, errors.Error("no local address")
	}

	errsPtr := s.errsPool.Get()
	defer s.errsPool.Put(errsPtr)

	*errsPtr = (*errsPtr)[:0]
	for _, b := range s.bound {
		if !b.pref.Contains(ip) {
			continue
		}

		cert, err = s.certForBinding(b, chi, ip)
		if err == nil {
			return cert, nil
		}

		*errsPtr = append(*errsPtr, err)
	}

	err = s.handleErrors(*errsPtr, chi, ip)
	if err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("no certificate found for %s", ip)
}

// errCertNotFound is returned when a certificate could not be found due to
// errors.
const errCertNotFound = errors.Error("certificate not found due to errors")

// handleErrors checks the list of errors encountered while trying to find a
// certificate for the given chi and ip.  If any errors are encountered,
// [errCertNotFound] is returned.  Original errors are logged if the logger is
// enabled.  chi must not be nil.
func (s *certIndex) handleErrors(
	errs []error,
	chi *tls.ClientHelloInfo,
	ip netip.Addr,
) (err error) {
	if len(errs) == 0 {
		return nil
	}

	ctx := chi.Context()
	// Do not use [optslog.Debug3] here to avoid [errors.Join] allocations
	// on every call.
	if s.logger.Enabled(ctx, slog.LevelDebug) {
		s.logger.DebugContext(
			ctx,
			"cert not found due to errors",
			"server_ip", ip,
			"client_sni", chi.ServerName,
			"errs", errors.Join(errs...),
		)
	}

	return errCertNotFound
}

// laddrFromConn returns the local address either from the packet session, if
// one can be obtained from the remote address, or from the connection itself.
// c must not be nil.
//
// This kind of original solution is necessary when working with
// SO_BINDTODEVICE.
//
// TODO(a.garipov):  Consolidate all these crutches somewhere.  Perhaps, netext.
func laddrFromConn(c net.Conn) (laddr net.Addr) {
	g, ok := c.RemoteAddr().(netext.PacketSessionGetter)
	if !ok {
		return c.LocalAddr()
	}

	s := g.PacketSession()

	return s.LocalAddr()
}

// certForBinding returns the TLS certificate for the given b and chi.  b and
// chi must not be nil.
func (s *certIndex) certForBinding(
	b *bindData,
	chi *tls.ClientHelloInfo,
	ip netip.Addr,
) (cert *tls.Certificate, err error) {
	certData, ok := s.certs.get(b.name)
	if !ok {
		panic(fmt.Errorf("certificate %q: %w", b.name, errors.ErrNoValue))
	}

	cert = certData.cert

	// [tls.ClientHelloInfo.SupportsCertificate] does not check against cert
	// fields [x509.Certificate.DNSNames] and [x509.Certificate.IPAddresses] if
	// ServerName is absent, which can lead to a false match.  Check the known
	// conditions before using it.
	//
	// See AGDNS-4617.
	if chi.ServerName == "" {
		leaf := cert.Leaf
		if len(leaf.IPAddresses) == 0 {
			// If the certificate doesn't have any IP addresses, do not return
			// it, as it obviously doesn't match.
			return nil, errors.Error("no server name in client hello for cert with no ip addrs")
		}

		// Check the IP address properly.
		err = leaf.VerifyHostname(ip.String())
		if err != nil {
			return nil, fmt.Errorf("checking cert with no servername: %w", err)
		}
	}

	err = chi.SupportsCertificate(cert)
	if err != nil {
		return nil, err
	}

	return cert, nil
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

// remove deletes the certificate from s by name.  removed is true if a
// certificate with the given name was presented in index.  name must be valid.
func (s *certIndex) remove(name agd.CertificateName) (removed bool) {
	removed = s.certs.del(name)
	s.bound = slices.DeleteFunc(s.bound, func(b *bindData) (found bool) {
		return b.name == name
	})

	return removed
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
