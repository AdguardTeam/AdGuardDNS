// Package cmd is the AdGuard DNS entry point.  It contains the on-disk
// configuration file utilities, signal processing logic, and so on.
package cmd

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/debugsvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
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

	agd.InitRequestID()

	// Log only to stdout and let users decide how to process it.
	log.SetOutput(os.Stdout)

	envs, err := readEnvs()
	check(err)

	envs.configureLogs()

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

	sigHdlr := newSignalHandler()

	// GeoIP database

	// We start GeoIP initialization early in a dedicated routine cause it takes
	// time, later we wait for completion and continue with GeoIP.
	//
	// See AGDNS-884.

	geoIP, geoIPRefr := &geoip.File{}, &agd.RefreshWorker{}
	geoIPErrCh := make(chan error, 1)

	go setupGeoIP(geoIP, geoIPRefr, geoIPErrCh, c.GeoIP, envs, errColl)

	// Safe-browsing and adult-blocking filters

	// TODO(ameshkov): Consider making configurable.
	filteringResolver := agdnet.NewCachingResolver(agdnet.DefaultResolver{}, 1*timeutil.Day)

	err = os.MkdirAll(envs.FilterCachePath, agd.DefaultDirPerm)
	check(err)

	// TODO(ameshkov): Consider making a separated max_size config for
	// safe-browsing and adult-blocking filters.
	maxFilterSize := int64(c.Filters.MaxSize.Bytes())

	safeBrowsingHashes, safeBrowsingFilter, err := setupHashPrefixFilter(
		c.SafeBrowsing,
		filteringResolver,
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
		filteringResolver,
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
		filteringResolver,
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
		filteringResolver,
		envs,
		safeBrowsingFilter,
		adultBlockingFilter,
		newRegDomainsFilter,
	)

	fltRefrTimeout := c.Filters.RefreshTimeout.Duration
	fltStrg, err := setupFilterStorage(fltStrgConf, sigHdlr, errColl, fltRefrTimeout)
	check(err)

	fltGroups, err := c.FilteringGroups.toInternal(fltStrg)
	check(err)

	// Network interface listener

	btdCtrlConf, ctrlConf := c.Network.toInternal()

	btdMgr, err := c.InterfaceListeners.toInternal(errColl, btdCtrlConf)
	check(err)

	err = btdMgr.Start()
	check(err)

	sigHdlr.add(btdMgr)

	// Server groups

	messages := dnsmsg.NewConstructor(&dnsmsg.BlockingModeNullIP{}, c.Filters.ResponseTTL.Duration)

	srvGrps, err := c.ServerGroups.toInternal(messages, btdMgr, fltGroups)
	check(err)

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

	profDB, billStatRec, err := setupBackend(c.Backend, envs, sigHdlr, errColl)
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

	sigHdlr.add(geoIPRefr)

	// Web service

	webConf, err := c.Web.toInternal(envs, dnsCk, errColl)
	check(err)

	webSvc := websvc.New(webConf)
	// The web service is considered critical, so its Start method panics
	// instead of returning an error.
	_ = webSvc.Start()

	sigHdlr.add(webSvc)

	// DNS service

	fwdConf, err := c.Upstream.toInternal()
	check(err)

	handler := forward.NewHandler(fwdConf)

	// TODO(a.garipov): Consider making these configurable via the configuration
	// file.
	hashStorages := map[string]*hashprefix.Storage{
		filter.GeneralTXTSuffix:       safeBrowsingHashes,
		filter.AdultBlockingTXTSuffix: adultBlockingHashes,
	}

	dnsConf := &dnssvc.Config{
		Messages:            messages,
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
		ConnLimiter:         connLimiter,
		FilteringGroups:     fltGroups,
		ServerGroups:        srvGrps,
		CacheSize:           c.Cache.Size,
		ECSCacheSize:        c.Cache.ECSSize,
		CacheMinTTL:         c.Cache.TTLOverride.Min.Duration,
		UseCacheTTLOverride: c.Cache.TTLOverride.Enabled,
		UseECSCache:         c.Cache.Type == cacheTypeECS,
		ResearchMetrics:     bool(envs.ResearchMetrics),
		ResearchLogs:        bool(envs.ResearchLogs),
		ControlConf:         ctrlConf,
	}

	dnsSvc, err := dnssvc.New(dnsConf)
	check(err)

	// Connectivity check

	err = connectivityCheck(dnsConf, c.ConnectivityCheck)
	check(err)

	upstreamHealthcheckUpd := newUpstreamHealthcheck(handler, c.Upstream, errColl)
	err = upstreamHealthcheckUpd.Start()
	check(err)

	sigHdlr.add(upstreamHealthcheckUpd)

	// The DNS service is considered critical, so its Start method panics
	// instead of returning an error.
	_ = dnsSvc.Start()

	sigHdlr.add(dnsSvc)

	// Debug HTTP-service

	debugSvc := debugsvc.New(envs.debugConf(dnsDB))

	// The debug HTTP service is considered critical, so its Start method panics
	// instead of returning an error.
	_ = debugSvc.Start()

	sigHdlr.add(debugSvc)

	// Signal that the server is started.
	metrics.SetUpGauge(
		agd.Version(),
		agd.BuildTime(),
		agd.Branch(),
		agd.Revision(),
		runtime.Version(),
	)

	os.Exit(sigHdlr.handle())
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
