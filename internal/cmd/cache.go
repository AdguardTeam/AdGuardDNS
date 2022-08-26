package cmd

import "fmt"

// Cache Configuration

// cacheConfig is the configuration of the DNS cacheConfig module
//
// TODO(a.garipov): Consider adding parameter Enabled or a new Type instead of
// relying on Size == 0 to disable cache.
type cacheConfig struct {
	// Type of cache to use.  See cacheType* constants.
	Type string `yaml:"type"`

	// Size is the size of the DNS cache for domain names that don't support
	// ECS, in entries.
	Size int `yaml:"size"`

	// ECSSize is the size of the DNS cache for domain names that support ECS,
	// in entries.
	ECSSize int `yaml:"ecs_size"`
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
		return nil
	}
}
