package cmd

import (
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/backend"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// Business Logic Backend Configuration

// backendConfig is the backend module configuration.
type backendConfig struct {
	// Timeout is the timeout for all outgoing HTTP requests.  Zero means no
	// timeout.
	Timeout timeutil.Duration `yaml:"timeout"`

	// RefreshIvl defines how often AdGuard DNS requests updates from the
	// backend.
	RefreshIvl timeutil.Duration `yaml:"refresh_interval"`

	// FullRefreshIvl defines how often AdGuard DNS performs full
	// synchronization.
	FullRefreshIvl timeutil.Duration `yaml:"full_refresh_interval"`

	// BillStatIvl defines how often AdGuard DNS sends the billing statistics to
	// the backend.
	BillStatIvl timeutil.Duration `yaml:"bill_stat_interval"`
}

// toInternal converts c to the data storage configuration for the DNS server.
// c is assumed to be valid.
func (c *backendConfig) toInternal(
	envs *environments,
	errColl agd.ErrorCollector,
) (profStrg *backend.ProfileStorageConfig, billStat *backend.BillStatConfig) {
	backendEndpoint := &envs.BackendEndpoint.URL

	return &backend.ProfileStorageConfig{
			BaseEndpoint: netutil.CloneURL(backendEndpoint),
			Now:          time.Now,
			ErrColl:      errColl,
		}, &backend.BillStatConfig{
			BaseEndpoint: netutil.CloneURL(backendEndpoint),
		}
}

// validate returns an error if the backend configuration is invalid.
func (c *backendConfig) validate() (err error) {
	switch {
	case c == nil:
		return errNilConfig
	case c.Timeout.Duration < 0:
		return newMustBeNonNegativeError("timeout", c.Timeout)
	case c.RefreshIvl.Duration <= 0:
		return newMustBePositiveError("refresh_interval", c.RefreshIvl)
	case c.FullRefreshIvl.Duration <= 0:
		return newMustBePositiveError("full_refresh_interval", c.FullRefreshIvl)
	case c.BillStatIvl.Duration <= 0:
		return newMustBePositiveError("bill_stat_interval", c.BillStatIvl)
	default:
		return nil
	}
}
