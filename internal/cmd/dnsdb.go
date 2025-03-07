package cmd

import (
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
)

// dnsDBConfig is the configuration of the DNSDB module.
type dnsDBConfig struct {
	// MaxSize is the maximum amount of records in the memory buffer.
	MaxSize int `yaml:"max_size"`

	// Enabled describes if the DNSDB memory buffer is enabled.
	Enabled bool `yaml:"enabled"`
}

// type check
var _ validate.Interface = (*dnsDBConfig)(nil)

// Validate implements the [validate.Interface] interface for *dnsDBConfig.
func (c *dnsDBConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	} else if !c.Enabled {
		return nil
	}

	return validate.Positive("max_size", c.MaxSize)
}
