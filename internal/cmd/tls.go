package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
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
func (c *tlsConfig) toInternal(
	ctx context.Context,
	tlsMgr tlsconfig.Manager,
) (deviceDomains []string, err error) {
	if c == nil {
		return nil, nil
	}

	err = c.Certificates.store(ctx, tlsMgr)
	if err != nil {
		return nil, fmt.Errorf("certificates: %w", err)
	}

	for _, w := range c.DeviceIDWildcards {
		deviceDomains = append(deviceDomains, strings.TrimPrefix(w, "*."))
	}

	return deviceDomains, nil
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
			return fmt.Errorf("at index %d: not a wildcard: %q", i, w)
		} else if s.Has(w) {
			return fmt.Errorf("at index %d: wildcard: %w: %q", i, errors.ErrDuplicated, w)
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

// store stores the TLS certificates in the TLS manager.  certs must be valid.
func (certs tlsConfigCerts) store(ctx context.Context, tlsMgr tlsconfig.Manager) (err error) {
	var errs []error
	for i, c := range certs {
		err = tlsMgr.Add(ctx, c.Certificate, c.Key)
		if err != nil {
			errs = append(errs, fmt.Errorf("adding certificate at index %d: %w", i, err))
		}
	}

	if len(errs) != 0 {
		return errors.Join(errs...)
	}

	return nil
}

// toInternal is like [tlsConfigCerts.store] but it also returns the TLS
// configuration.  certs must be valid.
func (certs tlsConfigCerts) toInternal(
	ctx context.Context,
	tlsMgr tlsconfig.Manager,
) (conf *tls.Config, err error) {
	if len(certs) == 0 {
		return nil, nil
	}

	err = certs.store(ctx, tlsMgr)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return tlsMgr.Clone(), nil
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
