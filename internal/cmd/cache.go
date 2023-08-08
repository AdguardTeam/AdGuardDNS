package cmd

import (
	"fmt"

	"github.com/AdguardTeam/golibs/timeutil"
)

// Cache Configuration

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

// validate returns an error if the cache configuration is invalid.
func (c *cacheConfig) validate() (err error) {
	switch {
	case c == nil:
		return errNilConfig
	case c.Type != cacheTypeSimple && c.Type != cacheTypeECS:
		return fmt.Errorf(
			"bad cache type %q, supported: %q",
			c.Type,
			[]string{cacheTypeSimple, cacheTypeECS},
		)
	case c.Size < 0:
		return newMustBeNonNegativeError("size", c.Size)
	case c.Type == cacheTypeECS && c.ECSSize < 0:
		return newMustBeNonNegativeError("ecs_size", c.ECSSize)
	default:
		// Go on.
	}

	err = c.TTLOverride.validate()
	if err != nil {
		return fmt.Errorf("ttl_override: %w", err)
	}

	return nil
}

// validate returns an error if the TTL override configuration is invalid.
func (c *ttlOverride) validate() (err error) {
	switch {
	case c == nil:
		return errNilConfig
	case c.Min.Duration <= 0:
		return newMustBePositiveError("min", c.Min)
	default:
		return nil
	}
}
