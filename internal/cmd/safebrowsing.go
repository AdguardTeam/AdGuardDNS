package cmd

import (
	"math"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/golibs/validate"
)

// safeBrowsingConfig is the configuration for one of the safe browsing filters.
type safeBrowsingConfig struct {
	// BlockHost is the hostname with which to respond to any requests that
	// match the filter.
	//
	// TODO(a.garipov): Consider replacing with a list of IPv4 and IPv6
	// addresses.
	BlockHost string `yaml:"block_host"`

	// CacheSize is the size of the response cache, in entries.  It must be
	// positive and less than or equal to [math.MaxInt].
	//
	// TODO(a.garipov):  Rename to "_count"?
	CacheSize uint64 `yaml:"cache_size"`

	// CacheTTL is the TTL of the response cache.
	CacheTTL timeutil.Duration `yaml:"cache_ttl"`

	// RefreshIvl defines how often AdGuard DNS refreshes the filter.
	RefreshIvl timeutil.Duration `yaml:"refresh_interval"`

	// RefreshTimeout is the timeout for the filter update operation.
	RefreshTimeout timeutil.Duration `yaml:"refresh_timeout"`
}

// type check
var _ validate.Interface = (*safeBrowsingConfig)(nil)

// Validate implements the [validate.Interface] interface for
// *safeBrowsingConfig.
func (c *safeBrowsingConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	return errors.Join(
		validate.NotEmpty("block_host", c.BlockHost),
		validate.Positive("cache_size", c.CacheSize),
		validate.NoGreaterThan("cache_size", c.CacheSize, math.MaxInt),
		validate.Positive("cache_ttl", c.CacheTTL),
		validate.Positive("refresh_interval", c.RefreshIvl),
		validate.Positive("refresh_timeout", c.RefreshTimeout),
	)
}
