package cmd

import (
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/golibs/validate"
)

// geoIPConfig is the GeoIP database configuration.
type geoIPConfig struct {
	// HostCacheSize is the size of the hostname lookup cache, in entries.
	//
	// TODO(a.garipov):  Rename to "host_cache_count"?
	HostCacheSize int `yaml:"host_cache_size"`

	// IPCacheSize is the size of the IP lookup cache, in entries.
	//
	// TODO(a.garipov):  Rename to "ip_cache_count"?
	IPCacheSize int `yaml:"ip_cache_size"`

	// RefreshIvl defines how often AdGuard DNS reopens the GeoIP database
	// files.
	RefreshIvl timeutil.Duration `yaml:"refresh_interval"`
}

// type check
var _ validate.Interface = (*geoIPConfig)(nil)

// Validate implements the [validate.Interface] interface for *geoIPConfig.
func (c *geoIPConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	return errors.Join(
		// NOTE:  While a [geoip.File] can work with an empty host cache, that
		// feature is only used for tests.
		validate.Positive("host_cache_size", c.HostCacheSize),
		validate.Positive("ip_cache_size", c.IPCacheSize),
		validate.Positive("refresh_interval", c.RefreshIvl),
	)
}
