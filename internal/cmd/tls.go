package cmd

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
)

// Possible values of the SESSION_TICKET_TYPE environment variable.
const (
	sessionTicketLocal  = "local"
	sessionTicketRemote = "remote"
)

// tlsCertificateConfig is a single TLS certificate configuration.
type tlsCertificateConfig struct {
	// CertificatePath is the path to the TLS certificate.
	CertificatePath string `yaml:"certificate"`

	// KeyPath is the path to the TLS private key.
	KeyPath string `yaml:"key"`
}

// certificateGroupConfigs is a map of certificate group names to their
// configurations.
type certificateGroupConfigs map[string]*tlsCertificateConfig

// tlsConfig is the common configuration of TLS certificates.
type tlsConfig struct {
	// CertificateGroups are the named groups of TLS certificates.
	CertificateGroups certificateGroupConfigs `yaml:"certificate_groups"`

	// Enabled is true if TLS is enabled.
	Enabled bool `yaml:"enabled"`
}

// store stores the TLS certificates in the TLS manager.  c must be valid,
// tlsMgr must not be nil.
func (c tlsConfig) store(ctx context.Context, tlsMgr tlsconfig.Manager) (err error) {
	var errs []error
	for name, conf := range c.CertificateGroups {
		err = tlsMgr.Add(ctx, &tlsconfig.AddParams{
			// The name is validated in [tlsConfig.Validate].
			Name:     agd.CertificateName(name),
			CertPath: conf.CertificatePath,
			KeyPath:  conf.KeyPath,
			IsCustom: false,
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("adding certificate %q: %w", name, err))
		}
	}

	return errors.Join(errs...)
}

// type check
var _ validate.Interface = (certificateGroupConfigs)(nil)

// Validate implements the [validate.Interface] interface for
// certificateGroupConfigs.
//
// TODO(e.burkov):  Consider checking the files existence with [os.Stat].
func (c certificateGroupConfigs) Validate() (err error) {
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(c)) {
		_, err = agd.NewCertificateName(name)
		if err != nil {
			errs = append(errs, fmt.Errorf("certificate group %q: %w", name, err))
		}

		cg := c[name]
		if cg == nil {
			errs = append(errs, fmt.Errorf("certificate group %q: %w", name, errors.ErrNoValue))

			continue
		}

		err = validate.NotEmpty("certificate", cg.CertificatePath)
		if err != nil {
			errs = append(errs, fmt.Errorf("certificate group %q: %w", name, err))
		}

		err = validate.NotEmpty("key", cg.KeyPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("certificate group %q: %w", name, err))
		}
	}

	return errors.Join(errs...)
}

// tlsCertificateGroupConfig defines a group of certificates used by a server
// group.
type tlsCertificateGroupConfig struct {
	Name agd.CertificateName `yaml:"name"`
}

// tlsCertificateGroupConfigs is a slice of certificate group configs.
type tlsCertificateGroupConfigs []*tlsCertificateGroupConfig

// validate returns an error if the certificate group configs are invalid.
func (c tlsCertificateGroupConfigs) validate(tlsConf *tlsConfig) (err error) {
	if c == nil {
		return errors.ErrNoValue
	} else if len(c) == 0 {
		return errors.ErrEmptyValue
	}

	var errs []error
	for i, cg := range c {
		nameStr := string(cg.Name)
		if _, ok := tlsConf.CertificateGroups[nameStr]; !ok {
			err = fmt.Errorf("at index %d: %q: %w", i, nameStr, errors.ErrBadEnumValue)
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// bind binds the certificate group configs to pref in tlsMgr.
func (c tlsCertificateGroupConfigs) bind(
	ctx context.Context,
	tlsMgr tlsconfig.Manager,
	pref netip.Prefix,
) (err error) {
	var errs []error
	for i, cg := range c {
		err = tlsMgr.Bind(ctx, cg.Name, pref)
		if err != nil {
			err = fmt.Errorf("at index %d: binding to %s: %w", i, pref, err)
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// serverGroupTLSConfig are the TLS settings of a DNS server, if any.
type serverGroupTLSConfig struct {
	// CertificateGroups are TLS certificate groups for this server.
	CertificateGroups tlsCertificateGroupConfigs `yaml:"certificate_groups"`

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
func (c *serverGroupTLSConfig) toInternal() (certNames []agd.CertificateName, wcDomains []string) {
	if c == nil {
		return nil, nil
	}

	for _, cg := range c.CertificateGroups {
		certNames = append(certNames, cg.Name)
	}

	for _, w := range c.DeviceIDWildcards {
		wcDomains = append(wcDomains, strings.TrimPrefix(w, "*."))
	}

	return certNames, wcDomains
}

// validateIfNecessary returns an error if the TLS configuration is invalid
// depending on whether it is necessary or not.
func (c *serverGroupTLSConfig) validateIfNecessary(
	needsTLS bool,
	tlsConf *tlsConfig,
	ts tlsState,
) (err error) {
	switch {
	case c == nil:
		if needsTLS {
			return errors.Error("server group requires tls")
		}

		// No TLS settings, which is normal.
		return nil
	case !needsTLS:
		return errors.Error("server group does not require tls")
	case ts == tlsStateDisabled:
		return errors.Error("tls is disabled")
	}

	var errs []error

	if ts == tlsStateValid {
		err = c.CertificateGroups.validate(tlsConf)
		if err != nil {
			errs = append(errs, fmt.Errorf("certificate_groups: %w", err))
		}
	}

	err = validateDeviceIDWildcards(c.DeviceIDWildcards)
	if err != nil {
		errs = append(errs, fmt.Errorf("device_id_wildcards: %w", err))
	}

	return errors.Join(errs...)
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

// tlsState is the state of TLS validation.
type tlsState string

// Valid tlsState values.
const (
	// tlsStateDisabled is the state of TLS validation when the TLS
	// configuration is not specified.
	tlsStateDisabled tlsState = "disabled"

	// tlsStateInvalid is the state of TLS validation when the result is
	// negative.
	tlsStateInvalid tlsState = "invalid"

	// tlsStateValid is the state of TLS validation when the result is positive.
	tlsStateValid tlsState = "valid"
)

// tlsConfigValidator validates the TLS configuration and updates the result's
type tlsConfigValidator struct {
	// tlsConf is the configuration to validate.
	tlsConf *tlsConfig

	// state is the state of TLS validation.  It must not be used until
	// [tlsConfigValidator.Validate] returns.
	state tlsState
}

// type check
var _ validate.Interface = (*tlsConfigValidator)(nil)

// Validate implements the [validate.Interface] interface for
// tlsConfigValidator.  It sets the state field of v to the corresponding
// tlsState value.
func (v *tlsConfigValidator) Validate() (err error) {
	if v.tlsConf == nil {
		v.state = tlsStateInvalid

		return errors.ErrNoValue
	}

	if !v.tlsConf.Enabled {
		v.state = tlsStateDisabled

		return nil
	}

	err = v.tlsConf.CertificateGroups.Validate()
	if err != nil {
		v.state = tlsStateInvalid
	} else {
		v.state = tlsStateValid
	}

	return err
}

// tlsValidator is like [validate.Interface], but accepts TLS configuration
// and state to validate the web module configuration with.
type tlsValidator interface {
	// validate returns error if the configuration is not valid.  tlsConf must
	// correspond to tlsState.
	validate(tlsConf *tlsConfig, tlsState *tlsState) (err error)
}

type validatorWithTLS struct {
	// validator is the entity to validate with TLS configuration.
	validator tlsValidator

	// tlsConf is the TLS configuration to validate with.
	tlsConf *tlsConfig

	// tlsState is the state of TLS validation.
	tlsState *tlsState
}

// type check
var _ validate.Interface = (*validatorWithTLS)(nil)

// Validate implements the [validate.Interface] interface for validatorWithTLS.
func (v validatorWithTLS) Validate() (err error) {
	return v.validator.validate(v.tlsConf, v.tlsState)
}
