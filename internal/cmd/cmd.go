// Package cmd is the AdGuard DNS entry point.  It contains the on-disk
// configuration file utilities, signal processing logic, and so on.
package cmd

import (
	"context"
	"os"
	"runtime"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/cmd/plugin"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/version"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// Main is the entry point of application.
func Main(plugins *plugin.Registry) {
	// TODO(a.garipov, e.burkov):  Consider adding timeouts for initialization.
	agd.InitRequestID()
	ctx := context.Background()

	// Log only to stdout and let users decide how to process it.
	log.SetOutput(os.Stdout)

	envs := errors.Must(parseEnvironment())

	errors.Check(envs.validate())

	// TODO(a.garipov):  Use slog everywhere.
	logger := envs.configureLogs()

	// TODO(a.garipov):  Consider ways of replacing a prefix and stop passing
	// the main logger everywhere.
	mainLogger := logger.With(slogutil.KeyPrefix, "main")

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

	errColl := errors.Must(envs.buildErrColl())

	defer reportPanics(ctx, errColl, mainLogger)

	c := errors.Must(parseConfig(envs.ConfPath))

	errors.Check(c.validate())

	errors.Check(envs.validateFromValidConfig(c))

	metrics.SetAdditionalInfo(c.AdditionalMetricsInfo)

	// Building and running the server

	b := newBuilder(&builderConfig{
		envs:       envs,
		conf:       c,
		baseLogger: logger,
		plugins:    plugins,
		errColl:    errColl,
	})

	b.startGeoIP(ctx)

	errors.Check(os.MkdirAll(envs.FilterCachePath, agd.DefaultDirPerm))

	errors.Check(b.initHashPrefixFilters(ctx))

	errors.Check(b.initFilterStorage(ctx))

	errors.Check(b.initFilteringGroups(ctx))

	errors.Check(b.initAccess(ctx))

	errors.Check(b.initBindToDevice(ctx))

	errors.Check(b.initMsgConstructor(ctx))

	errors.Check(b.initServerGroups(ctx))

	errors.Check(b.startBindToDevice(ctx))

	errors.Check(b.initTLS(ctx))

	errors.Check(b.initGRPCMetrics(ctx))

	errors.Check(b.initBillStat(ctx))

	errors.Check(b.initProfileDB(ctx))

	errors.Check(b.initDNSCheck(ctx))

	errors.Check(b.initRuleStat(ctx))

	errors.Check(b.initRateLimiter(ctx))

	errors.Check(b.initWeb(ctx))

	errors.Check(b.waitGeoIP(ctx))

	errors.Check(b.initDNS(ctx))

	errors.Check(b.performConnCheck(ctx))

	errors.Check(b.initHealthCheck(ctx))

	b.mustStartDNS(ctx)

	b.mustInitDebugSvc(ctx)

	// Signal that the server is started.
	metrics.SetUpGauge(buildVersion, commitTime, branch, revision, runtime.Version())

	os.Exit(b.handleSignals(ctx))
}
