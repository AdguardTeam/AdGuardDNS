package cmd

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
)

// dnsDBConfig is the configuration of the DNSDB module.
type dnsDBConfig struct {
	// MaxSize is the maximum amount of records in the memory buffer.
	MaxSize int `yaml:"max_size"`

	// Enabled describes if the DNSDB memory buffer is enabled.
	Enabled bool `yaml:"enabled"`
}

// validate returns an error if the configuration is invalid.
func (c *dnsDBConfig) validate() (err error) {
	switch {
	case c == nil:
		return errNilConfig
	case c.MaxSize <= 0:
		return newMustBePositiveError("size", c.MaxSize)
	default:
		return nil
	}
}

// toInternal builds and returns an anonymous statistics collector.
func (c *dnsDBConfig) toInternal(errColl errcoll.Interface) (d dnsdb.Interface) {
	if !c.Enabled {
		return dnsdb.Empty{}
	}

	db := dnsdb.New(&dnsdb.DefaultConfig{
		ErrColl: errColl,
		MaxSize: c.MaxSize,
	})

	return db
}
