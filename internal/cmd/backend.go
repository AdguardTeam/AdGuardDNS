package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/backend"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
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

// setupBackend creates and returns a profile database and a billing-statistics
// recorder as well as starts and registers their refreshers in the signal
// handler.
func setupBackend(
	conf *backendConfig,
	envs *environments,
	sigHdlr signalHandler,
	errColl agd.ErrorCollector,
) (profDB *agd.DefaultProfileDB, rec *billstat.RuntimeRecorder, err error) {
	profStrgConf, billStatConf := conf.toInternal(envs, errColl)
	rec = billstat.NewRuntimeRecorder(&billstat.RuntimeRecorderConfig{
		Uploader: backend.NewBillStat(billStatConf),
	})

	refrIvl := conf.RefreshIvl.Duration
	timeout := conf.Timeout.Duration
	billStatRefr := agd.NewRefreshWorker(&agd.RefreshWorkerConfig{
		Context: func() (ctx context.Context, cancel context.CancelFunc) {
			return context.WithTimeout(context.Background(), timeout)
		},
		Refresher:           rec,
		ErrColl:             errColl,
		Name:                "billstat",
		Interval:            refrIvl,
		RefreshOnShutdown:   true,
		RoutineLogsAreDebug: true,
	})
	err = billStatRefr.Start()
	if err != nil {
		return nil, nil, fmt.Errorf("starting bill stat recorder refresher: %w", err)
	}

	sigHdlr.add(billStatRefr)

	profStrg := backend.NewProfileStorage(profStrgConf)
	profDB, err = agd.NewDefaultProfileDB(
		profStrg,
		conf.FullRefreshIvl.Duration,
		envs.ProfilesCachePath,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating default profile database: %w", err)
	}

	profDBRefr := agd.NewRefreshWorker(&agd.RefreshWorkerConfig{
		Context: func() (ctx context.Context, cancel context.CancelFunc) {
			return context.WithTimeout(context.Background(), timeout)
		},
		Refresher:           profDB,
		ErrColl:             errColl,
		Name:                "profiledb",
		Interval:            refrIvl,
		RefreshOnShutdown:   false,
		RoutineLogsAreDebug: true,
	})
	err = profDBRefr.Start()
	if err != nil {
		return nil, nil, fmt.Errorf("starting default profile database refresher: %w", err)
	}

	sigHdlr.add(profDBRefr)

	return profDB, rec, nil
}
