package cmd

import (
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
)

// safeBrowsingConfig is the configuration for one of the safe browsing filters.
type safeBrowsingConfig struct {
	// BlockHost is the hostname with which to respond to any requests that
	// match the filter.
	//
	// TODO(a.garipov): Consider replacing with a list of IPv4 and IPv6
	// addresses.
	BlockHost string `yaml:"block_host"`

	// CacheSize is the size of the response cache, in entries.
	CacheSize int `yaml:"cache_size"`

	// CacheTTL is the TTL of the response cache.
	CacheTTL timeutil.Duration `yaml:"cache_ttl"`

	// RefreshIvl defines how often AdGuard DNS refreshes the filter.
	RefreshIvl timeutil.Duration `yaml:"refresh_interval"`

	// RefreshTimeout is the timeout for the filter update operation.
	RefreshTimeout timeutil.Duration `yaml:"refresh_timeout"`
}

// type check
var _ validator = (*safeBrowsingConfig)(nil)

// validate implements the [validator] interface for *safeBrowsingConfig.
func (c *safeBrowsingConfig) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case c.BlockHost == "":
		return fmt.Errorf("block_host: %w", errors.ErrEmptyValue)
	case c.CacheSize <= 0:
		return newNotPositiveError("cache_size", c.CacheSize)
	case c.CacheTTL.Duration <= 0:
		return newNotPositiveError("cache_ttl", c.CacheTTL)
	case c.RefreshIvl.Duration <= 0:
		return newNotPositiveError("refresh_interval", c.RefreshIvl)
	case c.RefreshTimeout.Duration <= 0:
		return newNotPositiveError("refresh_timeout", c.RefreshTimeout)
	default:
		return nil
	}
}
