package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// backendConfig is the backend module configuration.
//
// TODO(a.garipov): Reorganize this object as there is no longer the only one
// backend environment variable anymore.
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

	// FullRefreshRetryIvl is the interval between two retries of full
	// synchronizations.
	FullRefreshRetryIvl timeutil.Duration `yaml:"full_refresh_retry_interval"`

	// BillStatIvl defines how often AdGuard DNS sends the billing statistics to
	// the backend.
	BillStatIvl timeutil.Duration `yaml:"bill_stat_interval"`
}

// type check
var _ validator = (*backendConfig)(nil)

// validate implements the [validator] interface for *backendConfig.
func (c *backendConfig) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case c.Timeout.Duration < 0:
		return newNegativeError("timeout", c.Timeout)
	case c.RefreshIvl.Duration <= 0:
		return newNotPositiveError("refresh_interval", c.RefreshIvl)
	case c.FullRefreshIvl.Duration <= 0:
		return newNotPositiveError("full_refresh_interval", c.FullRefreshIvl)
	case c.FullRefreshRetryIvl.Duration <= 0:
		return newNotPositiveError("full_refresh_retry_interval", c.FullRefreshRetryIvl)
	case c.BillStatIvl.Duration <= 0:
		return newNotPositiveError("bill_stat_interval", c.BillStatIvl)
	default:
		return nil
	}
}

// initProfDB refreshes the profile database initially.  It logs an error if
// it's a timeout, and returns it otherwise.
func initProfDB(
	ctx context.Context,
	mainLogger *slog.Logger,
	profDB *profiledb.Default,
	timeout time.Duration,
) (err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	mainLogger.InfoContext(ctx, "initial profiledb refresh")

	err = profDB.Refresh(ctx)
	switch {
	case err == nil:
		mainLogger.InfoContext(ctx, "initial profiledb refresh succeeded")
	case errors.Is(err, context.DeadlineExceeded):
		mainLogger.WarnContext(ctx, "initial profiledb refresh timeout", slogutil.KeyError, err)
	default:
		return fmt.Errorf("initial refresh: %w", err)
	}

	return nil
}
