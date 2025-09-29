// Package cmd is the AdGuard DNS entry point.  It contains the on-disk
// configuration file utilities, signal processing logic, and so on.
package cmd

import (
	"context"
	"os"
	"os/signal"
	"runtime"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/cmd/plugin"
	"github.com/AdguardTeam/AdGuardDNS/internal/experiment"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/version"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/sentryutil"
	"golang.org/x/sys/unix"
)

// Main is the entry point of application.
func Main(plugins *plugin.Registry) {
	// TODO(a.garipov, e.burkov):  Consider adding timeouts for initialization.
	ctx, stop := signal.NotifyContext(context.Background(), unix.SIGINT, unix.SIGTERM)

	envs := errors.Must(parseEnvironment())
	errors.Check(envs.Validate())

	lvl := errors.Must(slogutil.VerbosityToLevel(envs.Verbosity))
	baseLogger := slogutil.New(&slogutil.Config{
		// Don't use [slogutil.NewFormat] here, because the value is validated.
		Format:       slogutil.Format(envs.LogFormat),
		AddTimestamp: bool(envs.LogTimestamp),
		Level:        lvl,
	})

	sentryutil.SetDefaultLogger(baseLogger, "")

	// TODO(a.garipov):  Consider ways of replacing a prefix and stop passing
	// the main logger everywhere.
	mainLogger := baseLogger.With(slogutil.KeyPrefix, "main")

	// Signal service startup now that we have the logs set up.
	branch := version.Branch()
	commitTime := version.CommitTime()
	buildVersion := version.Version()
	revision := version.Revision()
	mainLogger.InfoContext(
		ctx,
		"agdns starting",
		"version", buildVersion,
		"revision", revision,
		"branch", branch,
		"commit_time", commitTime,
		"race", version.RaceEnabled,
	)

	// Error collector
	//
	// TODO(a.garipov): Consider parsing SENTRY_DSN separately to set sentry up
	// first and collect panics from the readEnvs call above as well.

	errColl := errors.Must(envs.buildErrColl(baseLogger))

	defer reportPanics(ctx, errColl, mainLogger)

	setMaxThreads(ctx, mainLogger, envs.MaxThreads)

	c := errors.Must(parseConfig(envs.ConfPath))

	errors.Check(c.Validate())

	profilesEnabled := c.isProfilesEnabled()

	errors.Check(envs.validateProfilesConf(profilesEnabled))

	// Building and running the server

	b := newBuilder(&builderConfig{
		envs:            envs,
		conf:            c,
		baseLogger:      baseLogger,
		plugins:         plugins,
		errColl:         errColl,
		profilesEnabled: profilesEnabled,
	})

	errors.Check(b.initCrashReporter(ctx))

	errors.Check(experiment.Init(baseLogger, b.promRegisterer))

	errors.Check(metrics.SetAdditionalInfo(b.promRegisterer, c.AdditionalMetricsInfo))

	b.startGeoIP(ctx)

	errors.Check(os.MkdirAll(envs.FilterCachePath, agd.DefaultDirPerm))

	errors.Check(b.initMsgCloner(ctx))

	errors.Check(b.initHashPrefixFilters(ctx))

	errors.Check(b.initFilterStorage(ctx))

	errors.Check(b.initFilteringGroups(ctx))

	errors.Check(b.initAccess(ctx))

	errors.Check(b.initBindToDevice(ctx))

	errors.Check(b.initDNSDB(ctx))

	errors.Check(b.initQueryLog(ctx))

	errors.Check(b.initMsgConstructor(ctx))

	errors.Check(b.initGRPCMetrics(ctx))

	errors.Check(b.initStandardAccess(ctx))

	errors.Check(b.initTLSManager(ctx))

	errors.Check(b.initCustomDomainDB(ctx))

	errors.Check(b.initServerGroups(ctx))

	errors.Check(b.initTicketRotator(ctx))

	errors.Check(b.startBindToDevice(ctx))

	errors.Check(b.initBillStat(ctx))

	errors.Check(b.initProfileDB(ctx))

	errors.Check(b.refreshCustomDomainDB(ctx))

	errors.Check(b.initDNSCheck(ctx))

	errors.Check(b.initRuleStat(ctx))

	errors.Check(b.initRateLimiter(ctx))

	errors.Check(b.initWeb(ctx))

	errors.Check(b.waitGeoIP(ctx))

	errors.Check(b.initDNS(ctx))

	errors.Check(b.performConnCheck(ctx))

	errors.Check(b.initHealthCheck(ctx))

	errors.Check(b.initPluginServices(ctx))

	b.initPluginRefreshers()

	b.mustStartDNS(ctx)

	b.mustInitDebugSvc(ctx)

	// Signal that the server is started.
	errors.Check(metrics.SetUpGauge(
		b.promRegisterer,
		buildVersion,
		branch,
		commitTime,
		revision,
		runtime.Version(),
	))

	// Unregister the signal behavior for ctx.
	stop()
	ctx = context.WithoutCancel(ctx)

	os.Exit(b.handleSignals(ctx))
}
