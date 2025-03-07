package cmd

import (
	"fmt"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/golibs/validate"
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

// type check
var _ validate.Interface = (*ttlOverride)(nil)

// Validate implements the [validate.Interface] interface for *ttlOverride.
func (c *ttlOverride) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	return validate.Positive("min", c.Min)
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
		MinTTL:           time.Duration(c.TTLOverride.Min),
		ECSCount:         c.ECSSize,
		NoECSCount:       c.Size,
		Type:             typ,
		OverrideCacheTTL: c.TTLOverride.Enabled,
	}
}

// type check
var _ validate.Interface = (*cacheConfig)(nil)

// Validate implements the [validate.Interface] interface for *cacheConfig.
func (c *cacheConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	errs := []error{
		validate.NotNegative("size", c.Size),
	}

	errs = validate.Append(errs, "ttl_override", c.TTLOverride)

	switch c.Type {
	case cacheTypeSimple:
		// Go on.
	case cacheTypeECS:
		if err = validate.NotNegative("ecs_size", c.ECSSize); err != nil {
			// Don't wrap the error, because it's informative enough as is.
			errs = append(errs, err)
		}
	default:
		errs = append(errs, fmt.Errorf(
			"type: %w: %q, supported: %q",
			errors.ErrBadEnumValue,
			c.Type,
			[]string{cacheTypeSimple, cacheTypeECS},
		))
	}

	return errors.Join(errs...)
}
