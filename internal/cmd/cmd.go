// Package cmd is the AdGuard DNS entry point.  It contains the on-disk
// configuration file utilities, signal processing logic, and so on.
package cmd

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/debugsvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/service"
)

// Main is the entry point of application.
//
// TODO(a.garipov): Split into smaller pieces.
func Main() {
	// Initial Configuration

	agd.InitRequestID()

	// Log only to stdout and let users decide how to process it.
	log.SetOutput(os.Stdout)

	envs, err := readEnvs()
	check(err)

	// TODO(a.garipov): Use slog everywhere.
	slogLogger := envs.configureLogs()

	// Signal service startup now that we have the logs set up.
	log.Info("main: starting adguard dns")

	// Error collector
	//
	// TODO(a.garipov): Consider parsing SENTRY_DSN separately to set sentry up
	// first and collect panics from the readEnvs call above as well.

	errColl, err := envs.buildErrColl()
	check(err)

	defer collectPanics(errColl)

	// Configuration file

	c, err := readConfig(envs.ConfPath)
	check(err)

	err = c.validate()
	check(err)

	// Additional metrics

	metrics.SetAdditionalInfo(c.AdditionalMetricsInfo)

	// Signal handler

	sigHdlr := service.NewSignalHandler(&service.SignalHandlerConfig{
		Logger: slogLogger.With(slogutil.KeyPrefix, service.SignalHandlerPrefix),
	})

	// GeoIP database

	// We start GeoIP initialization early in a dedicated routine cause it takes
	// time, later we wait for completion and continue with GeoIP.
	//
	// See AGDNS-884.

	geoIP, geoIPRefr := &geoip.File{}, &agdservice.RefreshWorker{}
	geoIPErrCh := make(chan error, 1)

	go setupGeoIP(geoIP, geoIPRefr, geoIPErrCh, c.GeoIP, envs, errColl)

	// Safe-browsing and adult-blocking filters

	err = os.MkdirAll(envs.FilterCachePath, agd.DefaultDirPerm)
	check(err)

	// TODO(ameshkov): Consider making a separated max_size config for
	// safe-browsing and adult-blocking filters.
	maxFilterSize := c.Filters.MaxSize.Bytes()

	cloner := dnsmsg.NewCloner(metrics.ClonerStat{})
	safeBrowsingHashes, safeBrowsingFilter, err := setupHashPrefixFilter(
		c.SafeBrowsing,
		cloner,
		agd.FilterListIDSafeBrowsing,
		envs.SafeBrowsingURL,
		envs.FilterCachePath,
		maxFilterSize,
		sigHdlr,
		errColl,
	)
	check(err)

	adultBlockingHashes, adultBlockingFilter, err := setupHashPrefixFilter(
		c.AdultBlocking,
		cloner,
		agd.FilterListIDAdultBlocking,
		envs.AdultBlockingURL,
		envs.FilterCachePath,
		maxFilterSize,
		sigHdlr,
		errColl,
	)
	check(err)

	_, newRegDomainsFilter, err := setupHashPrefixFilter(
		// Reuse general safe browsing filter configuration.
		c.SafeBrowsing,
		cloner,
		agd.FilterListIDNewRegDomains,
		envs.NewRegDomainsURL,
		envs.FilterCachePath,
		maxFilterSize,
		sigHdlr,
		errColl,
	)
	check(err)

	// Filter storage and filtering groups

	fltStrgConf := c.Filters.toInternal(
		errColl,
		envs,
		safeBrowsingFilter,
		adultBlockingFilter,
		newRegDomainsFilter,
	)

	fltRefrTimeout := c.Filters.RefreshTimeout.Duration
	fltStrg, err := setupFilterStorage(fltStrgConf, sigHdlr, fltRefrTimeout)
	check(err)

	fltGroups, err := c.FilteringGroups.toInternal(fltStrg)
	check(err)

	// Access

	accessGlobal, err := access.NewGlobal(
		c.Access.BlockedQuestionDomains,
		netutil.UnembedPrefixes(c.Access.BlockedClientSubnets),
	)
	check(err)

	// Network interface listener and server groups

	messages := dnsmsg.NewConstructor(
		cloner,
		&dnsmsg.BlockingModeNullIP{},
		c.Filters.ResponseTTL.Duration,
	)

	btdCtrlConf, ctrlConf := c.Network.toInternal()

	btdMgr, err := c.InterfaceListeners.toInternal(errColl, btdCtrlConf)
	check(err)

	srvGrps, err := c.ServerGroups.toInternal(messages, btdMgr, fltGroups, c.RateLimit, c.DNS)
	check(err)

	ctx := context.Background()

	// Start the bind-to-device manager here, now that no further calls to
	// btdMgr.ListenConfig are required.
	err = btdMgr.Start(ctx)
	check(err)

	sigHdlr.Add(btdMgr)

	// TLS keys logging

	if envs.SSLKeyLogFile != "" {
		log.Info("IMPORTANT: TLS KEY LOGGING IS ENABLED; KEYS ARE DUMPED TO %q", envs.SSLKeyLogFile)
		err = enableTLSKeyLogging(srvGrps, envs.SSLKeyLogFile)
		check(err)
	}

	// TLS session-tickets rotation

	err = setupTicketRotator(srvGrps, sigHdlr, errColl)
	check(err)

	// Profiles database and billing statistics

	profDB, billStatRec, err := setupBackend(c.Backend, srvGrps, envs, sigHdlr, errColl)
	check(err)

	// DNS checker

	dnsCk, err := dnscheck.NewConsul(c.Check.toInternal(envs, messages, errColl))
	check(err)

	// DNSDB

	dnsDB := c.DNSDB.toInternal(errColl)

	// Filtering-rule statistics

	ruleStat, err := envs.buildRuleStat(sigHdlr, errColl)
	check(err)

	// Rate limiting

	consulAllowlistURL := &envs.ConsulAllowlistURL.URL
	rateLimiter, connLimiter, err := setupRateLimiter(c.RateLimit, consulAllowlistURL, sigHdlr, errColl)
	check(err)

	// GeoIP database

	// Wait for long-running GeoIP initialization.
	check(<-geoIPErrCh)

	sigHdlr.Add(geoIPRefr)

	// Web service

	webConf, err := c.Web.toInternal(envs, dnsCk, errColl)
	check(err)

	webSvc := websvc.New(webConf)
	// The web service is considered critical, so its Start method panics
	// instead of returning an error.
	_ = webSvc.Start(ctx)

	sigHdlr.Add(webSvc)

	// DNS service

	fwdConf := c.Upstream.toInternal()

	handler := forward.NewHandler(fwdConf)

	// TODO(a.garipov): Consider making these configurable via the configuration
	// file.
	hashStorages := map[string]*hashprefix.Storage{
		filter.GeneralTXTSuffix:       safeBrowsingHashes,
		filter.AdultBlockingTXTSuffix: adultBlockingHashes,
	}

	dnsConf := &dnssvc.Config{
		Messages:            messages,
		Cloner:              cloner,
		ControlConf:         ctrlConf,
		ConnLimiter:         connLimiter,
		AccessManager:       accessGlobal,
		SafeBrowsing:        hashprefix.NewMatcher(hashStorages),
		BillStat:            billStatRec,
		ProfileDB:           profDB,
		DNSCheck:            dnsCk,
		NonDNS:              webSvc,
		DNSDB:               dnsDB,
		ErrColl:             errColl,
		FilterStorage:       fltStrg,
		GeoIP:               geoIP,
		Handler:             handler,
		QueryLog:            c.buildQueryLog(envs),
		RuleStat:            ruleStat,
		RateLimit:           rateLimiter,
		FilteringGroups:     fltGroups,
		ServerGroups:        srvGrps,
		HandleTimeout:       c.DNS.HandleTimeout.Duration,
		CacheSize:           c.Cache.Size,
		ECSCacheSize:        c.Cache.ECSSize,
		CacheMinTTL:         c.Cache.TTLOverride.Min.Duration,
		UseCacheTTLOverride: c.Cache.TTLOverride.Enabled,
		UseECSCache:         c.Cache.Type == cacheTypeECS,
		ProfileDBEnabled:    bool(envs.ProfilesEnabled),
	}

	dnsSvc, err := dnssvc.New(dnsConf)
	check(err)

	// Connectivity check

	err = connectivityCheck(dnsConf, c.ConnectivityCheck)
	check(err)

	upstreamHealthcheckUpd := newUpstreamHealthcheck(handler, c.Upstream, errColl)
	err = upstreamHealthcheckUpd.Start(ctx)
	check(err)

	sigHdlr.Add(upstreamHealthcheckUpd)

	// The DNS service is considered critical, so its Start method panics
	// instead of returning an error.
	_ = dnsSvc.Start(ctx)

	sigHdlr.Add(dnsSvc)

	// Debug HTTP-service

	debugSvc := debugsvc.New(envs.debugConf(dnsDB))

	// The debug HTTP service is considered critical, so its Start method panics
	// instead of returning an error.
	_ = debugSvc.Start(ctx)

	sigHdlr.Add(debugSvc)

	// Signal that the server is started.
	metrics.SetUpGauge(
		agd.Version(),
		agd.BuildTime(),
		agd.Branch(),
		agd.Revision(),
		runtime.Version(),
	)

	os.Exit(sigHdlr.Handle(ctx))
}

// collectPanics reports all panics in Main.  It should be called in a defer.
//
// TODO(a.garipov): Consider making into a helper in package agd and using
// everywhere.
func collectPanics(errColl errcoll.Interface) {
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

	errFlushColl, ok := errColl.(errcoll.ErrorFlushCollector)
	if ok {
		errFlushColl.Flush()
	}

	panic(v)
}
