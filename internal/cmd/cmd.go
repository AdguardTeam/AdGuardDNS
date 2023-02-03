// Package cmd is the AdGuard DNS entry point.  It contains the on-disk
// configuration file utilities, signal processing logic, and so on.
package cmd

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/backend"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/AdGuardDNS/internal/consul"
	"github.com/AdguardTeam/AdGuardDNS/internal/debugsvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/timeutil"
)

// Main is the entry point of application.
//
// TODO(a.garipov): Split into smaller pieces.
func Main() {
	// Initial Configuration

	rand.Seed(time.Now().UnixNano())

	// Log only to stdout and let users decide how to process it.
	log.SetOutput(os.Stdout)

	envs, err := readEnvs()
	check(err)

	envs.configureLogs()

	// Signal service startup now that we have the logs set up.
	log.Info("main: starting adguard dns")

	// Error Collector
	//
	// TODO(a.garipov): Consider parsing SENTRY_DSN separately to set sentry up
	// first and collect panics from the readEnvs call above as well.

	errColl, err := envs.buildErrColl()
	check(err)

	defer collectPanics(errColl)

	// Configuration File

	c, err := readConfig(envs.ConfPath)
	check(err)

	err = c.validate()
	check(err)

	// Additional Metrics

	metrics.SetAdditionalInfo(c.AdditionalMetricsInfo)

	// GeoIP Database

	// We start GeoIP initialization early in a dedicated routine cause it
	// takes time, later we wait for completion and continue with GeoIP.
	//
	// See AGDNS-884.

	geoIPMu := &sync.Mutex{}

	var (
		geoIP    *geoip.File
		geoIPErr error
	)

	geoIPMu.Lock()
	go func() {
		defer geoIPMu.Unlock()

		geoIP, geoIPErr = envs.geoIP(c.GeoIP)
	}()

	// Safe-browsing and adult-blocking filters

	// TODO(ameshkov): Consider making configurable.
	filteringResolver := agdnet.NewCachingResolver(
		agdnet.DefaultResolver{},
		1*timeutil.Day,
	)

	err = os.MkdirAll(envs.FilterCachePath, agd.DefaultDirPerm)
	check(err)

	safeBrowsingConf, err := c.SafeBrowsing.toInternal(
		errColl,
		filteringResolver,
		agd.FilterListIDSafeBrowsing,
		envs.FilterCachePath,
	)
	check(err)

	safeBrowsingFilter, err := filter.NewHashPrefix(safeBrowsingConf)
	check(err)

	safeBrowsingUpd := agd.NewRefreshWorker(&agd.RefreshWorkerConfig{
		Context:             ctxWithDefaultTimeout,
		Refresher:           safeBrowsingFilter,
		ErrColl:             errColl,
		Name:                string(agd.FilterListIDSafeBrowsing),
		Interval:            safeBrowsingConf.Staleness,
		RefreshOnShutdown:   false,
		RoutineLogsAreDebug: false,
	})
	err = safeBrowsingUpd.Start()
	check(err)

	adultBlockingConf, err := c.AdultBlocking.toInternal(
		errColl,
		filteringResolver,
		agd.FilterListIDAdultBlocking,
		envs.FilterCachePath,
	)
	check(err)

	adultBlockingFilter, err := filter.NewHashPrefix(adultBlockingConf)
	check(err)

	adultBlockingUpd := agd.NewRefreshWorker(&agd.RefreshWorkerConfig{
		Context:             ctxWithDefaultTimeout,
		Refresher:           adultBlockingFilter,
		ErrColl:             errColl,
		Name:                string(agd.FilterListIDAdultBlocking),
		Interval:            adultBlockingConf.Staleness,
		RefreshOnShutdown:   false,
		RoutineLogsAreDebug: false,
	})
	err = adultBlockingUpd.Start()
	check(err)

	// Filter storage and filtering groups

	fltStrgConf := c.Filters.toInternal(
		errColl,
		filteringResolver,
		envs,
		safeBrowsingFilter,
		adultBlockingFilter,
	)

	fltStrg, err := filter.NewDefaultStorage(fltStrgConf)
	check(err)

	fltStrgUpd := agd.NewRefreshWorker(&agd.RefreshWorkerConfig{
		Context: func() (ctx context.Context, cancel context.CancelFunc) {
			return context.WithTimeout(context.Background(), c.Filters.RefreshTimeout.Duration)
		},
		Refresher:           fltStrg,
		ErrColl:             errColl,
		Name:                "filters",
		Interval:            fltStrgConf.RefreshIvl,
		RefreshOnShutdown:   false,
		RoutineLogsAreDebug: false,
	})
	err = fltStrgUpd.Start()
	check(err)

	// Server Groups

	fltGroups, err := c.FilteringGroups.toInternal(fltStrg)
	check(err)

	messages := &dnsmsg.Constructor{
		FilteredResponseTTL: c.Filters.ResponseTTL.Duration,
	}

	srvGrps, err := c.ServerGroups.toInternal(messages, fltGroups)
	check(err)

	// TLS keys logging

	if envs.SSLKeyLogFile != "" {
		log.Info("IMPORTANT: TLS KEY LOGGING IS ENABLED; KEYS ARE DUMPED TO %q", envs.SSLKeyLogFile)
		err = enableTLSKeyLogging(srvGrps, envs.SSLKeyLogFile)
		check(err)
	}

	// TLS Session Tickets Rotation

	tickRot, err := newTicketRotator(srvGrps)
	check(err)

	tickRotUpd := agd.NewRefreshWorker(&agd.RefreshWorkerConfig{
		Context:   ctxWithDefaultTimeout,
		Refresher: tickRot,
		ErrColl:   errColl,
		Name:      "tickrot",
		// TODO(ameshkov): Consider making configurable.
		Interval:            1 * time.Minute,
		RefreshOnShutdown:   false,
		RoutineLogsAreDebug: true,
	})
	err = tickRotUpd.Start()
	check(err)

	// Profiles Database

	profStrgConf, billStatConf := c.Backend.toInternal(envs, errColl)
	profStrg := backend.NewProfileStorage(profStrgConf)

	// Billing Statistics

	billStatRec := billstat.NewRuntimeRecorder(&billstat.RuntimeRecorderConfig{
		Uploader: backend.NewBillStat(billStatConf),
	})

	billStatRecUpd := agd.NewRefreshWorker(&agd.RefreshWorkerConfig{
		Context:             ctxWithDefaultTimeout,
		Refresher:           billStatRec,
		ErrColl:             errColl,
		Name:                "billstat",
		Interval:            c.Backend.BillStatIvl.Duration,
		RefreshOnShutdown:   true,
		RoutineLogsAreDebug: true,
	})
	err = billStatRecUpd.Start()
	check(err)

	profDB, err := agd.NewDefaultProfileDB(
		profStrg,
		c.Backend.FullRefreshIvl.Duration,
		envs.ProfilesCachePath,
	)
	check(err)

	profDBUpd := agd.NewRefreshWorker(&agd.RefreshWorkerConfig{
		Context: func() (ctx context.Context, cancel context.CancelFunc) {
			return context.WithTimeout(context.Background(), c.Backend.Timeout.Duration)
		},
		Refresher:           profDB,
		ErrColl:             errColl,
		Name:                "profiledb",
		Interval:            c.Backend.RefreshIvl.Duration,
		RefreshOnShutdown:   false,
		RoutineLogsAreDebug: true,
	})
	err = profDBUpd.Start()
	check(err)

	// Query Log

	queryLog := c.buildQueryLog(envs)

	// DNS Checker

	dnsCk, err := dnscheck.NewConsul(c.Check.toInternal(envs, messages, errColl))
	check(err)

	// DNSDB

	dnsDB, dnsDBUpd := envs.buildDNSDB(errColl)
	err = dnsDBUpd.Start()
	check(err)

	// Filtering Rule Statistics

	ruleStat, ruleStatUpd := envs.ruleStat(errColl)
	err = ruleStatUpd.Start()
	check(err)

	// Rate Limiting

	allowSubnets, err := agdnet.ParseSubnets(c.RateLimit.Allowlist.List...)
	check(err)

	allowlist := ratelimit.NewDynamicAllowlist(allowSubnets, nil)
	allowlistRefresher, err := consul.NewAllowlistRefresher(allowlist, &envs.ConsulAllowlistURL.URL)
	check(err)

	allowlistUpd := agd.NewRefreshWorker(&agd.RefreshWorkerConfig{
		Context:             ctxWithDefaultTimeout,
		Refresher:           allowlistRefresher,
		ErrColl:             errColl,
		Name:                "allowlist",
		Interval:            c.RateLimit.Allowlist.RefreshIvl.Duration,
		RefreshOnShutdown:   false,
		RoutineLogsAreDebug: false,
	})
	err = allowlistUpd.Start()
	check(err)

	rateLimiter := ratelimit.NewBackOff(c.RateLimit.toInternal(allowlist))

	// GeoIP Database

	// Wait for long-running GeoIP initialization.
	geoIPMu.Lock()
	defer geoIPMu.Unlock()

	check(geoIPErr)

	geoIPUpd := agd.NewRefreshWorker(&agd.RefreshWorkerConfig{
		Context:             ctxWithDefaultTimeout,
		Refresher:           geoIP,
		ErrColl:             errColl,
		Name:                "geoip",
		Interval:            c.GeoIP.RefreshIvl.Duration,
		RefreshOnShutdown:   false,
		RoutineLogsAreDebug: false,
	})
	err = geoIPUpd.Start()
	check(err)

	// Web Service

	webConf, err := c.Web.toInternal(envs, dnsCk, errColl)
	check(err)

	webSvc := websvc.New(webConf)
	// The web service is considered critical, so its Start method panics
	// instead of returning an error.
	_ = webSvc.Start()

	// DNS Service

	metricsListener := prometheus.NewForwardMetricsListener(len(c.Upstream.FallbackServers) + 1)

	upstream, err := c.Upstream.toInternal()
	check(err)

	handler := forward.NewHandler(&forward.HandlerConfig{
		Address:                    upstream.Server,
		Network:                    upstream.Network,
		MetricsListener:            metricsListener,
		HealthcheckDomainTmpl:      c.Upstream.Healthcheck.DomainTmpl,
		FallbackAddresses:          c.Upstream.FallbackServers,
		Timeout:                    c.Upstream.Timeout.Duration,
		HealthcheckBackoffDuration: c.Upstream.Healthcheck.BackoffDuration.Duration,
	}, c.Upstream.Healthcheck.Enabled)

	dnsConf := &dnssvc.Config{
		Messages: messages,
		SafeBrowsing: filter.NewSafeBrowsingServer(
			safeBrowsingConf.Hashes,
			adultBlockingConf.Hashes,
		),
		BillStat:        billStatRec,
		ProfileDB:       profDB,
		DNSCheck:        dnsCk,
		NonDNS:          webSvc,
		DNSDB:           dnsDB,
		ErrColl:         errColl,
		FilterStorage:   fltStrg,
		GeoIP:           geoIP,
		Handler:         handler,
		QueryLog:        queryLog,
		RuleStat:        ruleStat,
		Upstream:        upstream,
		RateLimit:       rateLimiter,
		FilteringGroups: fltGroups,
		ServerGroups:    srvGrps,
		CacheSize:       c.Cache.Size,
		ECSCacheSize:    c.Cache.ECSSize,
		UseECSCache:     c.Cache.Type == cacheTypeECS,
		ResearchMetrics: bool(envs.ResearchMetrics),
	}

	dnsSvc, err := dnssvc.New(dnsConf)
	check(err)

	err = connectivityCheck(dnsConf, c.ConnectivityCheck)
	check(err)

	upstreamHealthcheckUpd := newUpstreamHealthcheck(handler, c.Upstream, errColl)
	err = upstreamHealthcheckUpd.Start()
	check(err)

	// The DNS service is considered critical, so its Start method panics
	// instead of returning an error.
	_ = dnsSvc.Start()

	// Debug HTTP Service

	debugSvc := debugsvc.New(envs.debugConf(dnsDB))

	// The debug HTTP service is considered critical, so its Start method panics
	// instead of returning an error.
	_ = debugSvc.Start()

	// Signal that the server is started.
	metrics.SetUpGauge(
		agd.Version(),
		agd.BuildTime(),
		agd.Branch(),
		agd.Revision(),
		runtime.Version(),
	)

	h := newSignalHandler(
		debugSvc,
		webSvc,
		dnsSvc,
		safeBrowsingUpd,
		adultBlockingUpd,
		profDBUpd,
		dnsDBUpd,
		geoIPUpd,
		ruleStatUpd,
		allowlistUpd,
		fltStrgUpd,
		tickRotUpd,
		billStatRecUpd,
	)

	os.Exit(h.handle())
}

// collectPanics reports all panics in Main.  It should be called in a defer.
//
// TODO(a.garipov): Consider making into a helper in package agd and using
// everywhere.
func collectPanics(errColl agd.ErrorCollector) {
	v := recover()
	if v == nil {
		return
	}

	err, ok := v.(error)
	if ok {
		err = fmt.Errorf("panic in cmd.Main: %w", err)
	} else {
		err = fmt.Errorf("panic in cmd.Main: %v", v)
	}

	errColl.Collect(context.Background(), err)

	panic(v)
}

// defaultTimeout is the timeout used for some operations where another timeout
// hasn't been defined yet.
const defaultTimeout = 30 * time.Second

// ctxWithDefaultTimeout is a helper function that returns a context with
// timeout set to defaultTimeout.
func ctxWithDefaultTimeout() (ctx context.Context, cancel context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultTimeout)
}
