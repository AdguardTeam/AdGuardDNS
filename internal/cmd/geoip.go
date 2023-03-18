package cmd

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/timeutil"
)

// GeoIP database configuration

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

// validate returns an error if the GeoIP database configuration is invalid.
func (c *geoIPConfig) validate() (err error) {
	switch {
	case c == nil:
		return errNilConfig
	case c.HostCacheSize <= 0:
		// Note that while geoip.File can work with an empty host cache, that
		// feature is only used for tests.
		return newMustBePositiveError("host_cache_size", c.HostCacheSize)
	case c.IPCacheSize <= 0:
		return newMustBePositiveError("ip_cache_size", c.IPCacheSize)
	case c.RefreshIvl.Duration <= 0:
		return newMustBePositiveError("refresh_interval", c.RefreshIvl)
	default:
		return nil
	}
}

// setupGeoIP creates and sets the GeoIP database as well as creates and starts
// its refresher.  It is intended to be used as a goroutine.  geoIPPtr and
// refrPtr must not be nil.  errCh receives nil if the database and the
// refresher have been created successfully or an error if not.
func setupGeoIP(
	geoIPPtr *geoip.File,
	refrPtr *agd.RefreshWorker,
	errCh chan<- error,
	conf *geoIPConfig,
	envs *environments,
	errColl agd.ErrorCollector,
) {
	geoIP, err := envs.geoIP(conf)
	if err != nil {
		errCh <- fmt.Errorf("creating geoip: %w", err)

		return
	}

	refr := agd.NewRefreshWorker(&agd.RefreshWorkerConfig{
		Context:             ctxWithDefaultTimeout,
		Refresher:           geoIP,
		ErrColl:             errColl,
		Name:                "geoip",
		Interval:            conf.RefreshIvl.Duration,
		RefreshOnShutdown:   false,
		RoutineLogsAreDebug: false,
	})
	err = refr.Start()
	if err != nil {
		errCh <- fmt.Errorf("starting geoip refresher: %w", err)

		return
	}

	*geoIPPtr, *refrPtr = *geoIP, *refr

	errCh <- nil
}
