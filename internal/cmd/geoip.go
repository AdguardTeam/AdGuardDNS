package cmd

import (
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
)

// geoIPConfig is the GeoIP database configuration.
type geoIPConfig struct {
	// HostCacheSize is the size of the hostname lookup cache, in entries.
	HostCacheSize int `yaml:"host_cache_size"`

	// IPCacheSize is the size of the IP lookup cache, in entries.
	IPCacheSize int `yaml:"ip_cache_size"`

	// RefreshIvl defines how often AdGuard DNS reopens the GeoIP database
	// files.
	RefreshIvl timeutil.Duration `yaml:"refresh_interval"`
}

// type check
var _ validator = (*geoIPConfig)(nil)

// validate implements the [validator] interface for *geoIPConfig.
func (c *geoIPConfig) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case c.HostCacheSize <= 0:
		// Note that while geoip.File can work with an empty host cache, that
		// feature is only used for tests.
		return newNotPositiveError("host_cache_size", c.HostCacheSize)
	case c.IPCacheSize <= 0:
		return newNotPositiveError("ip_cache_size", c.IPCacheSize)
	case c.RefreshIvl.Duration <= 0:
		return newNotPositiveError("refresh_interval", c.RefreshIvl)
	default:
		return nil
	}
}
