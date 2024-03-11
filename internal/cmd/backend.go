package cmd

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
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
	apiURL := netutil.CloneURL(&envs.BillStatURL.URL)
	billStatUploader, err := setupBillStatUploader(apiURL, errColl)
	if err != nil {
		return nil, fmt.Errorf("creating bill stat uploader: %w", err)
	}

	rec = billstat.NewRuntimeRecorder(&billstat.RuntimeRecorderConfig{
		Uploader: billStatUploader,
	})

	refrIvl := conf.RefreshIvl.Duration
	timeout := conf.Timeout.Duration

	billStatRefr := agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		Context: func() (ctx context.Context, cancel context.CancelFunc) {
			return context.WithTimeout(context.Background(), timeout)
		},
		Refresher:           rec,
		ErrColl:             errColl,
		Name:                "billstat",
		Interval:            refrIvl,
		RefreshOnShutdown:   true,
		RoutineLogsAreDebug: true,
		RandomizeStart:      false,
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
	apiURL := netutil.CloneURL(&envs.ProfilesURL.URL)
	bindSet := collectBindSubnetSet(grps)
	profStrg, err := setupProfStorage(apiURL, bindSet, errColl)
	if err != nil {
		return nil, fmt.Errorf("creating profile storage: %w", err)
	}

	timeout := conf.Timeout.Duration
	profDB, err = profiledb.New(&profiledb.Config{
		Storage:          profStrg,
		FullSyncIvl:      conf.FullRefreshIvl.Duration,
		FullSyncRetryIvl: conf.FullRefreshRetryIvl.Duration,
		InitialTimeout:   timeout,
		CacheFilePath:    envs.ProfilesCachePath,
	})
	if err != nil {
		return nil, fmt.Errorf("creating default profile database: %w", err)
	}

	refrIvl := conf.RefreshIvl.Duration

	profDBRefr := agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		Context: func() (ctx context.Context, cancel context.CancelFunc) {
			return context.WithTimeout(context.Background(), timeout)
		},
		Refresher:           profDB,
		ErrColl:             errColl,
		Name:                "profiledb",
		Interval:            refrIvl,
		RefreshOnShutdown:   false,
		RoutineLogsAreDebug: true,
		RandomizeStart:      true,
	})
	err = profDBRefr.Start(context.Background())
	if err != nil {
		return nil, fmt.Errorf("starting default profile database refresher: %w", err)
	}

	sigHdlr.Add(profDBRefr)

	return profDB, nil
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

// setupProfStorage creates and returns a profile storage depending on the
// provided API URL.
func setupProfStorage(
	apiURL *url.URL,
	bindSet netutil.SubnetSet,
	errColl errcoll.Interface,
) (s profiledb.Storage, err error) {
	scheme := apiURL.Scheme
	if scheme == schemeGRPC || scheme == schemeGRPCS {
		return backendpb.NewProfileStorage(&backendpb.ProfileStorageConfig{
			BindSet:  bindSet,
			Endpoint: apiURL,
			ErrColl:  errColl,
		})
	}

	return nil, fmt.Errorf("invalid backend api url: %s", apiURL)
}

// setupBillStatUploader creates and returns a billstat uploader depending on
// the provided API URL.
func setupBillStatUploader(
	apiURL *url.URL,
	errColl errcoll.Interface,
) (s billstat.Uploader, err error) {
	scheme := apiURL.Scheme
	if scheme == schemeGRPC || scheme == schemeGRPCS {
		return backendpb.NewBillStat(&backendpb.BillStatConfig{
			ErrColl:  errColl,
			Endpoint: apiURL,
		})
	}

	return nil, fmt.Errorf("invalid backend api url: %s", apiURL)
}
