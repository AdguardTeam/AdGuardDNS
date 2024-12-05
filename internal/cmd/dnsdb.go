package cmd

import (
	"log/slog"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// dnsDBConfig is the configuration of the DNSDB module.
type dnsDBConfig struct {
	// MaxSize is the maximum amount of records in the memory buffer.
	MaxSize int `yaml:"max_size"`

	// Enabled describes if the DNSDB memory buffer is enabled.
	Enabled bool `yaml:"enabled"`
}

// type check
var _ validator = (*dnsDBConfig)(nil)

// validate implements the [validator] interface for *dnsDBConfig.
func (c *dnsDBConfig) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case !c.Enabled:
		return nil
	case c.MaxSize <= 0:
		return newNotPositiveError("size", c.MaxSize)
	default:
		return nil
	}
}

// toInternal builds and returns an anonymous statistics collector.  c must be
// valid.
func (c *dnsDBConfig) toInternal(
	baseLogger *slog.Logger,
	errColl errcoll.Interface,
) (d dnsdb.Interface) {
	if !c.Enabled {
		return dnsdb.Empty{}
	}

	db := dnsdb.New(&dnsdb.DefaultConfig{
		Logger:  baseLogger.With(slogutil.KeyPrefix, "dnsdb"),
		ErrColl: errColl,
		MaxSize: c.MaxSize,
	})

	return db
}
