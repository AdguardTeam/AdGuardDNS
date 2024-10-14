package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// tlsConfig are the TLS settings of a DNS server, if any.
type tlsConfig struct {
	// Certificates are TLS certificates for this server.
	Certificates tlsConfigCerts `yaml:"certificates"`

	// SessionKeys are paths to files containing the TLS session keys for this
	// server.
	SessionKeys []string `yaml:"session_keys"`

	// DeviceIDWildcards are the wildcard domains that are used to infer device
	// IDs from the clients' server names.
	//
	// TODO(a.garipov):  Validate the actual DNS Names in the certificates
	// against these?
	//
	// TODO(a.garipov):  Replace with just domain names, since the "*." isn't
	// really necessary at all.
	DeviceIDWildcards []string `yaml:"device_id_wildcards"`
}

// toInternal converts c to the TLS configuration for a DNS server.  c must be
// valid.
func (c *tlsConfig) toInternal() (conf *agd.TLS, err error) {
	if c == nil {
		return nil, nil
	}

	tlsConf, err := c.Certificates.toInternal()
	if err != nil {
		return nil, fmt.Errorf("certificates: %w", err)
	}

	var deviceDomains []string
	for _, w := range c.DeviceIDWildcards {
		deviceDomains = append(deviceDomains, strings.TrimPrefix(w, "*."))
	}

	return &agd.TLS{
		Conf:          tlsConf,
		DeviceDomains: deviceDomains,
		SessionKeys:   c.SessionKeys,
	}, nil
}

// validate returns an error if the TLS configuration is invalid for the given
// protocol.
func (c *tlsConfig) validate(needsTLS bool) (err error) {
	switch {
	case c == nil:
		if needsTLS {
			return errors.Error("server group requires tls")
		}

		// No TLS settings, which is normal.
		return nil
	case !needsTLS:
		return errors.Error("server group does not require tls")
	}

	if len(c.Certificates) == 0 {
		return fmt.Errorf("certificates: %w", errors.ErrEmptyValue)
	}

	err = c.Certificates.validate()
	if err != nil {
		return fmt.Errorf("certificates: %w", err)
	}

	err = validateDeviceIDWildcards(c.DeviceIDWildcards)
	if err != nil {
		return fmt.Errorf("device_id_wildcards: %w", err)
	}

	return nil
}

// validateDeviceIDWildcards returns an error if the device ID domain wildcards
// are invalid.
func validateDeviceIDWildcards(wildcards []string) (err error) {
	s := container.NewMapSet[string]()
	for i, w := range wildcards {
		// TODO(e.burkov):  Consider removing this requirement.
		if !strings.HasPrefix(w, "*.") {
			return fmt.Errorf("at index %d: not a wildcard", i)
		} else if s.Has(w) {
			return fmt.Errorf("at index %d: duplicated wildcard", i)
		}

		s.Add(w)
	}

	return nil
}

// tlsConfigCert is a single TLS certificate.
type tlsConfigCert struct {
	// Certificate is the path to the TLS certificate.
	Certificate string `yaml:"certificate"`

	// Key is the path to the TLS private key.
	Key string `yaml:"key"`
}

// tlsConfigCerts are TLS certificates.  A valid instance of tlsConfigCerts has
// no nil items.
type tlsConfigCerts []*tlsConfigCert

// toInternal converts certs to a TLS configuration.  certs must be valid.
func (certs tlsConfigCerts) toInternal() (conf *tls.Config, err error) {
	if len(certs) == 0 {
		return nil, nil
	}

	tlsCerts := make([]tls.Certificate, len(certs))
	for i, c := range certs {
		var cert tls.Certificate
		cert, err = tls.LoadX509KeyPair(c.Certificate, c.Key)
		if err != nil {
			return nil, fmt.Errorf("certificate at index %d: %w", i, err)
		}

		var leaf *x509.Certificate
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("invalid leaf, certificate at index %d: %w", i, err)
		}

		cert.Leaf = leaf
		tlsCerts[i] = cert

		authAlgo, subj := leaf.PublicKeyAlgorithm.String(), leaf.Subject.String()
		metrics.TLSCertificateInfo.With(prometheus.Labels{
			"auth_algo": authAlgo,
			"subject":   subj,
		}).Set(1)
		metrics.TLSCertificateNotAfter.With(prometheus.Labels{
			"subject": subj,
		}).Set(float64(leaf.NotAfter.Unix()))
	}

	return &tls.Config{
		Certificates: tlsCerts,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}, nil
}

// type check
var _ validator = tlsConfigCerts(nil)

// validate implements the [validator] interface for tlsConfigCerts.
func (certs tlsConfigCerts) validate() (err error) {
	for i, c := range certs {
		switch {
		case c == nil:
			return fmt.Errorf("at index %d: %w", i, errors.ErrNoValue)
		case c.Certificate == "":
			return fmt.Errorf("at index %d: certificate: %w", i, errors.ErrEmptyValue)
		case c.Key == "":
			return fmt.Errorf("at index %d: key: %w", i, errors.ErrEmptyValue)
		}
	}

	return nil
}

// enableTLSKeyLogging enables TLS key logging (use for debug purposes only).
func enableTLSKeyLogging(grps []*agd.ServerGroup, keyLogFileName string) (err error) {
	path := filepath.Clean(keyLogFileName)

	// TODO(a.garipov): Consider closing the file when we add SIGHUP support.
	kl, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("opening SSL_KEY_LOG_FILE: %w", err)
	}

	for _, g := range grps {
		for _, s := range g.Servers {
			if s.TLS != nil {
				s.TLS.KeyLogWriter = kl
			}
		}
	}

	return nil
}
