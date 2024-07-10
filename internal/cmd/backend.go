package cmd

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/timeutil"
)

// Business Logic Backend Configuration

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
	case c.FullRefreshRetryIvl.Duration <= 0:
		return newMustBePositiveError("full_refresh_retry_interval", c.FullRefreshRetryIvl)
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
	grps []*agd.ServerGroup,
	envs *environments,
	sigHdlr *service.SignalHandler,
	errColl errcoll.Interface,
) (profDB profiledb.Interface, rec billstat.Recorder, err error) {
	if !envs.ProfilesEnabled {
		return &profiledb.Disabled{}, billstat.EmptyRecorder{}, nil
	}

	rec, err = setupBillStat(conf, envs, sigHdlr, errColl)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, nil, err
	}

	profDB, err = setupProfDB(conf, grps, envs, sigHdlr, errColl)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, nil, err
	}

	return profDB, rec, nil
}

// setupBillStat creates and returns a billing-statistics recorder as well as
// starts and registers its refresher in the signal handler.
func setupBillStat(
	conf *backendConfig,
	envs *environments,
	sigHdlr *service.SignalHandler,
	errColl errcoll.Interface,
) (rec *billstat.RuntimeRecorder, err error) {
	billStatUploader, err := setupBillStatUploader(envs, errColl)
	if err != nil {
		return nil, fmt.Errorf("creating bill stat uploader: %w", err)
	}

	rec = billstat.NewRuntimeRecorder(&billstat.RuntimeRecorderConfig{
		ErrColl:  errColl,
		Uploader: billStatUploader,
	})

	refrIvl := conf.RefreshIvl.Duration
	timeout := conf.Timeout.Duration

	billStatRefr := agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		Context: func() (ctx context.Context, cancel context.CancelFunc) {
			return context.WithTimeout(context.Background(), timeout)
		},
		Refresher:         rec,
		Name:              "billstat",
		Interval:          refrIvl,
		RefreshOnShutdown: true,
		RandomizeStart:    false,
	})
	err = billStatRefr.Start(context.Background())
	if err != nil {
		return nil, fmt.Errorf("starting bill stat recorder refresher: %w", err)
	}

	sigHdlr.Add(billStatRefr)

	return rec, nil
}

// setupProfDB creates and returns a profile database as well as starts and
// registers its refresher in the signal handler.
func setupProfDB(
	conf *backendConfig,
	grps []*agd.ServerGroup,
	envs *environments,
	sigHdlr *service.SignalHandler,
	errColl errcoll.Interface,
) (profDB *profiledb.Default, err error) {
	bindSet := collectBindSubnetSet(grps)
	profStrg, err := setupProfStorage(envs, bindSet, errColl)
	if err != nil {
		return nil, fmt.Errorf("creating profile storage: %w", err)
	}

	timeout := conf.Timeout.Duration
	profDB, err = profiledb.New(&profiledb.Config{
		Storage:          profStrg,
		ErrColl:          errColl,
		FullSyncIvl:      conf.FullRefreshIvl.Duration,
		FullSyncRetryIvl: conf.FullRefreshRetryIvl.Duration,
		CacheFilePath:    envs.ProfilesCachePath,
	})
	if err != nil {
		return nil, fmt.Errorf("creating default profile database: %w", err)
	}

	err = initProfDB(profDB, timeout)
	if err != nil {
		return nil, fmt.Errorf("preparing default profile database: %w", err)
	}

	profDBRefr := agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		Context: func() (ctx context.Context, cancel context.CancelFunc) {
			return context.WithTimeout(context.Background(), timeout)
		},
		Refresher:         profDB,
		Name:              "profiledb",
		Interval:          conf.RefreshIvl.Duration,
		RefreshOnShutdown: false,
		RandomizeStart:    true,
	})
	err = profDBRefr.Start(context.Background())
	if err != nil {
		return nil, fmt.Errorf("starting default profile database refresher: %w", err)
	}

	sigHdlr.Add(profDBRefr)

	return profDB, nil
}

// initProfDB refreshes the profile database initially.  It logs an error if
// it's a timeout, and returns it otherwise.
func initProfDB(profDB *profiledb.Default, timeout time.Duration) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	log.Info("main: initial profiledb refresh")

	err = profDB.Refresh(ctx)
	switch {
	case err == nil:
		log.Info("main: initial profiledb refresh succeeded")
	case errors.Is(err, context.DeadlineExceeded):
		log.Info("main: warning: initial profiledb refresh timeout: %s", err)
	default:
		return fmt.Errorf("initial refresh: %w", err)
	}

	return nil
}

// collectBindSubnetSet returns a subnet set with IP addresses of servers in the
// provided server groups grps.
func collectBindSubnetSet(grps []*agd.ServerGroup) (s netutil.SubnetSet) {
	var serverPrefixes []netip.Prefix
	allSingleIP := true
	for _, grp := range grps {
		for _, srv := range grp.Servers {
			for _, p := range srv.BindDataPrefixes() {
				allSingleIP = allSingleIP && p.IsSingleIP()
				serverPrefixes = append(serverPrefixes, p)
			}
		}
	}

	// In cases where an installation only has single-IP prefixes in bind
	// interfaces, or no bind interfaces at all, only check the dedicated IPs in
	// profiles for validity.
	//
	// TODO(a.garipov): Do not load profiles on such installations at all, as
	// they don't really need them.  See AGDNS-1888.
	if allSingleIP {
		log.Info("warning: all bind ifaces are single-ip; only checking validity of dedicated ips")

		return netutil.SubnetSetFunc(netip.Addr.IsValid)
	}

	return netutil.SliceSubnetSet(serverPrefixes)
}

// Backend API URL schemes.
const (
	schemeGRPC  = "grpc"
	schemeGRPCS = "grpcs"
)

// setupBillStatUploader creates and returns a billstat uploader depending on
// the provided API URL.
func setupBillStatUploader(
	envs *environments,
	errColl errcoll.Interface,
) (s billstat.Uploader, err error) {
	apiURL := netutil.CloneURL(&envs.BillStatURL.URL)
	scheme := apiURL.Scheme
	if scheme == schemeGRPC || scheme == schemeGRPCS {
		return backendpb.NewBillStat(&backendpb.BillStatConfig{
			ErrColl:  errColl,
			Endpoint: apiURL,
			APIKey:   envs.BillStatAPIKey,
		})
	}

	return nil, fmt.Errorf("invalid backend api url: %s", apiURL)
}

// setupProfStorage creates and returns a profile storage depending on the
// provided API URL.
func setupProfStorage(
	envs *environments,
	bindSet netutil.SubnetSet,
	errColl errcoll.Interface,
) (s profiledb.Storage, err error) {
	apiURL := netutil.CloneURL(&envs.ProfilesURL.URL)
	scheme := apiURL.Scheme
	if scheme == schemeGRPC || scheme == schemeGRPCS {
		return backendpb.NewProfileStorage(&backendpb.ProfileStorageConfig{
			BindSet:  bindSet,
			ErrColl:  errColl,
			Endpoint: apiURL,
			APIKey:   envs.ProfilesAPIKey,
		})
	}

	return nil, fmt.Errorf("invalid backend api url: %s", apiURL)
}
