package cmd

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
)

// cacheConfig is the configuration of the DNS cacheConfig module
//
// TODO(a.garipov): Consider adding parameter Enabled or a new Type instead of
// relying on Size == 0 to disable cache.
type cacheConfig struct {
	// TTLOverride is a section with the settings for cache item TTL overrides.
	TTLOverride *ttlOverride `yaml:"ttl_override"`

	// Type of cache to use.  See cacheType* constants.
	Type string `yaml:"type"`

	// Size is the size of the DNS cache for domain names that don't support
	// ECS, in entries.
	Size int `yaml:"size"`

	// ECSSize is the size of the DNS cache for domain names that support ECS,
	// in entries.
	ECSSize int `yaml:"ecs_size"`
}

// ttlOverride represents TTL override configuration.
type ttlOverride struct {
	// Min describes the minimum duration for cache item TTL.
	Min timeutil.Duration `yaml:"min"`

	// Enabled returns true if the cache item TTL could be overwritten with Min
	// value.
	Enabled bool `yaml:"enabled"`
}

// Cache types.
const (
	cacheTypeECS    = "ecs"
	cacheTypeSimple = "simple"
)

// toInternal converts c to the cache configuration for the DNS server.  c must
// be valid.
func (c *cacheConfig) toInternal() (cacheConf *dnssvc.CacheConfig) {
	var typ dnssvc.CacheType
	if c.Size == 0 {
		// TODO(a.garipov):  Add as a type in the configuration file.
		typ = dnssvc.CacheTypeNone
	} else if c.Type == cacheTypeSimple {
		typ = dnssvc.CacheTypeSimple
	} else {
		typ = dnssvc.CacheTypeECS
	}

	return &dnssvc.CacheConfig{
		MinTTL:           c.TTLOverride.Min.Duration,
		ECSCount:         c.ECSSize,
		NoECSCount:       c.Size,
		Type:             typ,
		OverrideCacheTTL: c.TTLOverride.Enabled,
	}
}

// type check
var _ validator = (*cacheConfig)(nil)

// validate implements the [validator] interface for *cacheConfig.
func (c *cacheConfig) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case c.Type != cacheTypeSimple && c.Type != cacheTypeECS:
		return fmt.Errorf(
			"type: %w: %q, supported: %q",
			errors.ErrBadEnumValue,
			c.Type,
			[]string{cacheTypeSimple, cacheTypeECS},
		)
	case c.Size < 0:
		return newNegativeError("size", c.Size)
	case c.Type == cacheTypeECS && c.ECSSize < 0:
		return newNegativeError("ecs_size", c.ECSSize)
	default:
		// Go on.
	}

	err = c.TTLOverride.validate()
	if err != nil {
		return fmt.Errorf("ttl_override: %w", err)
	}

	return nil
}

// type check
var _ validator = (*ttlOverride)(nil)

// validate implements the [validator] interface for *ttlOverride.
func (c *ttlOverride) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case c.Min.Duration <= 0:
		return newNotPositiveError("min", c.Min)
	default:
		return nil
	}
}
