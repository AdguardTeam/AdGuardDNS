package cmd

import (
	"fmt"
	"os"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/ameshkov/dnscrypt/v2"
	"gopkg.in/yaml.v2"
)

// dnsCryptConfig are the DNSCrypt server settings.
type dnsCryptConfig struct {
	// Inline is the inline configuration.  Must be empty if ConfigPath is not
	// empty.
	Inline *dnscrypt.ResolverConfig `yaml:"inline"`

	// ConfigPath is the path to the DNSCrypt configuration file.  Must be empty
	// if Inline is not empty.
	ConfigPath string `yaml:"config_path"`
}

// toInternal converts c to the DNSCrypt configuration for a DNS server.  c must
// be valid.
func (c *dnsCryptConfig) toInternal() (conf *agd.DNSCryptConfig, err error) {
	if c == nil {
		return nil, nil
	}

	var rc *dnscrypt.ResolverConfig
	if c.Inline == nil {
		var f *os.File
		f, err = os.Open(c.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("opening dnscrypt config: %w", err)
		}
		defer func() { err = errors.WithDeferred(err, f.Close()) }()

		rc = &dnscrypt.ResolverConfig{}
		err = yaml.NewDecoder(f).Decode(rc)
		if err != nil {
			return nil, fmt.Errorf("decoding dnscrypt config: %w", err)
		}

		err = validateDNSCrypt(rc)
		if err != nil {
			return nil, fmt.Errorf("validating dnscrypt config: %w", err)
		}
	} else {
		rc = c.Inline
	}

	var cert *dnscrypt.Cert
	cert, err = rc.CreateCert()
	if err != nil {
		return nil, fmt.Errorf("creating dnscrypt cert: %w", err)
	}

	return &agd.DNSCryptConfig{
		Cert:         cert,
		ProviderName: rc.ProviderName,
	}, nil
}

// validateForProtocol returns an error if the DNSCrypt configuration is invalid
// for the given protocol.
func (c *dnsCryptConfig) validateForProtocol(p serverProto) (err error) {
	needsDC := p == srvProtoDNSCrypt
	switch {
	case c == nil:
		if needsDC {
			return fmt.Errorf("protocol %s requires dnscrypt", p)
		}

		// No DNSCrypt settings, which is normal.
		return nil
	case !needsDC:
		return fmt.Errorf("protocol %s does not require dnscrypt", p)
	case (c.ConfigPath == "") == (c.Inline == nil):
		return errors.Error("must provide either config_path or inline")
	}

	if c.Inline != nil {
		err = validateDNSCrypt(c.Inline)
		if err != nil {
			return fmt.Errorf("inline: %w", err)
		}
	}

	return nil
}

// validateDNSCrypt validates DNSCrypt resolver configuration.  rc must not be
// nil.
func validateDNSCrypt(rc *dnscrypt.ResolverConfig) (err error) {
	errs := []error{
		validate.NotEmpty("provider_name", rc.ProviderName),
		validate.NotEmpty("public_key", rc.PublicKey),
		validate.NotEmpty("private_key", rc.PrivateKey),
	}

	if rc.EsVersion != dnscrypt.XChacha20Poly1305 && rc.EsVersion != dnscrypt.XSalsa20Poly1305 {
		errs = append(errs, fmt.Errorf("es_version: %w: %d", errors.ErrBadEnumValue, rc.EsVersion))
	}

	return errors.Join(errs...)
}
