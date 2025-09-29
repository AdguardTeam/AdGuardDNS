package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net/netip"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/AdGuardDNS/internal/cmd/plugin"
	"github.com/AdguardTeam/AdGuardDNS/internal/connlimiter"
	"github.com/AdguardTeam/AdGuardDNS/internal/consul"
	"github.com/AdguardTeam/AdGuardDNS/internal/debugsvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	dnssvcprom "github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterstorage"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/AdGuardDNS/internal/rulestat"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
	"github.com/AdguardTeam/golibs/contextutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/mathutil/randutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/c2h5oh/datasize"
	"github.com/prometheus/client_golang/prometheus"
)

// Constants that define debug identifiers for the debug HTTP service.
const (
	debugIDAllowlist             = "allowlist"
	debugIDBillStat              = "billstat"
	debugIDCustomDomainDB        = "custom_domain_db"
	debugIDGeoIP                 = "geoip"
	debugIDProfileDB             = "profiledb"
	debugIDProfileDBFull         = "profiledb_full"
	debugIDRuleStat              = "rulestat"
	debugIDStandardProfileAccess = "standard_profile_access"
	debugIDTLSConfig             = "tlsconfig"
	debugIDTicketRotator         = "ticket_rotator"
	debugIDWebSvc                = "websvc"

	// debugIDPrefixPlugin is the prefix for plugin debug identifiers.
	debugIDPrefixPlugin = "plugin/"
)

// builder contains the logic of configuring and combining together AdGuard DNS
// entities.
//
// NOTE:  Keep method definitions in the rough order in which they are intended
// to be called.
//
// TODO(a.garipov):  Consider putting some of the setupFoo, envs.buildFoo, and
// foo.toInternal methods' contents in here.
type builder struct {
	// The fields below are initialized immediately on construction.  Keep them
	// sorted.

	baseLogger     *slog.Logger
	cacheManager   *agdcache.DefaultManager
	conf           *configuration
	debugRefrs     debugsvc.Refreshers
	env            *environment
	errColl        errcoll.Interface
	geoIPError     chan error
	logger         *slog.Logger
	mtrcNamespace  string
	plugins        *plugin.Registry
	promRegisterer prometheus.Registerer
	rand           *rand.Rand
	sigHdlr        *service.SignalHandler
	standardAccess access.Blocker

	// The fields below are initialized later by calling the builder's methods.
	// Keep them sorted.

	access               *access.Global
	adultBlocking        *hashprefix.Filter
	adultBlockingHashes  *hashprefix.Storage
	backendGRPCMtrc      backendpb.GRPCMetrics
	billStat             billstat.Recorder
	bindSet              netutil.SubnetSet
	btdManager           *bindtodevice.Manager
	cloner               *dnsmsg.Cloner
	connLimit            *connlimiter.Limiter
	controlConf          *netext.ControlConfig
	customDomainDB       *tlsconfig.CustomDomainDB
	dnsCheck             dnscheck.Interface
	dnsDB                dnsdb.Interface
	dnsSvc               *dnssvc.Service
	dnsSvcCustomDomainDB dnssvc.CustomDomainDB
	filterMtrc           filter.Metrics
	filterStorage        *filterstorage.Default
	filteringGroups      map[agd.FilteringGroupID]*agd.FilteringGroup
	fwdHandler           *forward.Handler
	geoIP                *geoip.File
	hashMatcher          *hashprefix.Matcher
	messages             *dnsmsg.Constructor
	newRegDomains        *hashprefix.Filter
	newRegDomainsHashes  *hashprefix.Storage
	profDBCustomDomainDB profiledb.CustomDomainDB
	profileDB            profiledb.Interface
	queryLog             querylog.Interface
	rateLimit            *ratelimit.Backoff
	ruleStat             rulestat.Interface
	safeBrowsing         *hashprefix.Filter
	safeBrowsingHashes   *hashprefix.Storage
	sdeConf              *dnsmsg.StructuredDNSErrorsConfig
	tlsManager           *tlsconfig.DefaultManager
	webSvc               *websvc.Service
	webSvcCertValidator  websvc.CertificateValidator

	// The fields below are initialized later, just like with the fields above,
	// but are placed in this order for alignment optimization.

	serverGroups    []*dnssvc.ServerGroupConfig
	profilesEnabled bool
}

// builderConfig contains the initial configuration for the builder.
type builderConfig struct {
	// envs contains the environment variables for the builder.  It must be
	// valid and must not be nil.
	envs *environment

	// conf contains the configuration from the configuration file for the
	// builder.  It must be valid and must not be nil.
	conf *configuration

	// baseLogger is used to create loggers for other entities.  It should not
	// have a prefix and must not be nil.
	baseLogger *slog.Logger

	// plugins is the registry of plugins to use, if any.
	plugins *plugin.Registry

	// errColl is used to collect errors in the entities.  It must not be nil.
	errColl errcoll.Interface

	// profilesEnabled is true if the configuration implies that the profiles
	// are enabled.
	profilesEnabled bool
}

// shutdownTimeout is the default shutdown timeout for all services.
const shutdownTimeout = 5 * time.Second

// newBuilder returns a new properly initialized builder.  c must not be nil.
func newBuilder(c *builderConfig) (b *builder) {
	return &builder{
		baseLogger:     c.baseLogger,
		cacheManager:   agdcache.NewDefaultManager(),
		conf:           c.conf,
		env:            c.envs,
		errColl:        c.errColl,
		geoIPError:     make(chan error, 1),
		logger:         c.baseLogger.With(slogutil.KeyPrefix, "builder"),
		mtrcNamespace:  metrics.Namespace(),
		plugins:        c.plugins,
		promRegisterer: prometheus.DefaultRegisterer,
		debugRefrs:     debugsvc.Refreshers{},
		// #nosec G115 G404 -- The Unix epoch time is highly unlikely to be
		// negative and we don't need a real random for simple refresh time
		// randomization.
		rand: rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 0)),
		sigHdlr: service.NewSignalHandler(&service.SignalHandlerConfig{
			Logger:          c.baseLogger.With(slogutil.KeyPrefix, service.SignalHandlerPrefix),
			ShutdownTimeout: shutdownTimeout,
		}),
		profilesEnabled: c.profilesEnabled,
	}
}

// initCrashReporter initializes the crash reporter.
func (b *builder) initCrashReporter(ctx context.Context) (err error) {
	crashRep, err := newCrashReporter(&crashReporterConfig{
		logger:  b.baseLogger.With(slogutil.KeyPrefix, "crash_reporter"),
		dirPath: b.env.CrashOutputDir,
		prefix:  b.env.CrashOutputPrefix,
		enabled: bool(b.env.CrashOutputEnabled),
	})
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	err = crashRep.Start(ctx)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	b.sigHdlr.AddService(crashRep)

	b.logger.DebugContext(ctx, "initialized crash reporter")

	return nil
}

// startGeoIP starts the concurrent initialization of the GeoIP database.  The
// GeoIP initialization is started early and concurrently, because it takes
// time.  Later methods wait for the completion and continue with GeoIP.
//
// See AGDNS-884.
func (b *builder) startGeoIP(ctx context.Context) {
	go b.initGeoIP(ctx)
}

// initGeoIP creates and sets the GeoIP database as well as creates and starts
// its refresher.  It is intended to be used as a goroutine.  When finished,
// [builder.geoIPError] receives nil if the database and the refresher have been
// created successfully or an error if not.
func (b *builder) initGeoIP(ctx context.Context) {
	defer slogutil.RecoverAndExit(ctx, b.logger, osutil.ExitCodeFailure)

	var err error
	defer func() { b.geoIPError <- err }()

	asn, ctry := b.env.GeoIPASNPath, b.env.GeoIPCountryPath
	b.logger.DebugContext(ctx, "using geoip files", "asn", asn, "ctry", ctry)

	mtrc, err := metrics.NewGeoIP(b.mtrcNamespace, b.promRegisterer, asn, ctry)
	if err != nil {
		err = fmt.Errorf("registering geoip metrics: %w", err)

		return
	}

	c := b.conf.GeoIP
	b.geoIP = geoip.NewFile(&geoip.FileConfig{
		Logger:         b.baseLogger.With(slogutil.KeyPrefix, "geoip"),
		Metrics:        mtrc,
		CacheManager:   b.cacheManager,
		ASNPath:        asn,
		CountryPath:    ctry,
		HostCacheCount: c.HostCacheSize,
		IPCacheCount:   c.IPCacheSize,
		AllTopASNs:     geoip.DefaultTopASNs,
		CountryTopASNs: geoip.DefaultCountryTopASNs,
	})

	err = b.geoIP.Refresh(ctx)
	if err != nil {
		err = fmt.Errorf("creating geoip: initial refresh: %w", err)

		return
	}

	b.logger.DebugContext(ctx, "initialized geoip")
}

// initMsgCloner initializes the DNS message cloner.
func (b *builder) initMsgCloner(ctx context.Context) (err error) {
	mtrc, err := metrics.NewClonerStat(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("initializing cloner: %w", err)
	}

	b.cloner = dnsmsg.NewCloner(mtrc)

	b.logger.DebugContext(ctx, "initialized cloner")

	return nil
}

// initHashPrefixFilters initializes the hashprefix storages and filters.
//
// [builder.initMsgCloner] must be called before this method.
func (b *builder) initHashPrefixFilters(ctx context.Context) (err error) {
	// TODO(a.garipov):  Make a separate max_size config for hashprefix filters.
	maxSize := b.conf.Filters.MaxSize
	cacheDir := b.env.FilterCachePath

	matchers := map[string]*hashprefix.Storage{}

	b.filterMtrc, err = metrics.NewFilter(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("registering filter metrics: %w", err)
	}

	// TODO(a.garipov):  Merge the three functions below together.

	err = b.initAdultBlocking(ctx, matchers, maxSize, cacheDir)
	if err != nil {
		return fmt.Errorf("initializing adult-blocking filter: %w", err)
	}

	err = b.initNewRegDomains(ctx, maxSize, cacheDir)
	if err != nil {
		return fmt.Errorf("initializing newly-registered domain filter: %w", err)
	}

	err = b.initSafeBrowsing(ctx, matchers, maxSize, cacheDir)
	if err != nil {
		return fmt.Errorf("initializing safe-browsing filter: %w", err)
	}

	b.hashMatcher = hashprefix.NewMatcher(matchers)

	b.logger.DebugContext(ctx, "initialized hash prefixes")

	return nil
}

// initAdultBlocking initializes the adult-blocking filter and hash storage.  It
// also adds the refresher with ID
// [hashprefix.IDPrefix]/[filter.IDAdultBlocking] to the debug refreshers.
//
// It must be called from [builder.initHashPrefixFilters].
func (b *builder) initAdultBlocking(
	ctx context.Context,
	matchers map[string]*hashprefix.Storage,
	maxSize datasize.ByteSize,
	cacheDir string,
) (err error) {
	if !b.env.AdultBlockingEnabled {
		return nil
	}

	b.adultBlockingHashes, err = hashprefix.NewStorage(nil)
	if err != nil {
		// Expect no errors here because we pass a nil.
		panic(err)
	}

	c := b.conf.AdultBlocking
	refrIvl := time.Duration(c.RefreshIvl)
	refrTimeout := time.Duration(c.RefreshTimeout)

	const id = filter.IDAdultBlocking

	hashPrefMtcs, err := metrics.NewHashPrefixFilter(
		b.mtrcNamespace,
		string(id),
		b.promRegisterer,
	)
	if err != nil {
		return fmt.Errorf("registering hashprefix filter metrics: %w", err)
	}

	prefix := path.Join(hashprefix.IDPrefix, string(id))

	b.adultBlocking, err = hashprefix.NewFilter(&hashprefix.FilterConfig{
		Logger:          b.baseLogger.With(slogutil.KeyPrefix, prefix),
		Cloner:          b.cloner,
		CacheManager:    b.cacheManager,
		Hashes:          b.adultBlockingHashes,
		URL:             &b.env.AdultBlockingURL.URL,
		ErrColl:         b.errColl,
		HashPrefixMtcs:  hashPrefMtcs,
		Metrics:         b.filterMtrc,
		ID:              id,
		CachePath:       filepath.Join(cacheDir, string(id)),
		ReplacementHost: c.BlockHost,
		Staleness:       refrIvl,
		RefreshTimeout:  refrTimeout,
		CacheTTL:        time.Duration(c.CacheTTL),
		// TODO(a.garipov):  Make all sizes [datasize.ByteSize] and rename cache
		// entity counts to fooCount.
		CacheCount: c.CacheSize,
		MaxSize:    maxSize,
	})
	if err != nil {
		return fmt.Errorf("creating filter: %w", err)
	}

	err = b.adultBlocking.RefreshInitial(ctx)
	if err != nil {
		return fmt.Errorf("initial refresh: %w", err)
	}

	refr := service.NewRefreshWorker(&service.RefreshWorkerConfig{
		// Note that we also set the same timeout for the http.Client in
		// [hashprefix.NewFilter].
		ContextConstructor: contextutil.NewTimeoutConstructor(refrTimeout),
		ErrorHandler:       newSlogErrorHandler(b.baseLogger, string(id)+"_refresh"),
		Refresher:          b.adultBlocking,
		Schedule:           timeutil.NewConstSchedule(refrIvl),
		RefreshOnShutdown:  false,
	})

	// TODO(a.garipov, e.burkov):  Consider using different context for child
	// routines.
	err = refr.Start(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("starting refresher: %w", err)
	}

	b.sigHdlr.AddService(refr)

	matchers[filter.AdultBlockingTXTSuffix] = b.adultBlockingHashes

	b.debugRefrs[prefix] = b.adultBlocking

	return nil
}

// newSlogErrorHandler is a convenient wrapper around
// [service.NewSlogErrorHandler].
func newSlogErrorHandler(baseLogger *slog.Logger, prefix string) (h *service.SlogErrorHandler) {
	return service.NewSlogErrorHandler(
		baseLogger.With(slogutil.KeyPrefix, prefix),
		slog.LevelError,
		"refreshing",
	)
}

// initNewRegDomains initializes the newly-registered domain filter and hash
// storage.  It also adds the refresher with ID
// [hashprefix.IDPrefix]/[filter.IDNewRegDomains] to the debug refreshers.
//
// It must be called from [builder.initHashPrefixFilters].
func (b *builder) initNewRegDomains(
	ctx context.Context,
	maxSize datasize.ByteSize,
	cacheDir string,
) (err error) {
	if !b.env.NewRegDomainsEnabled {
		return nil
	}

	b.newRegDomainsHashes, err = hashprefix.NewStorage(nil)
	if err != nil {
		// Don't expect errors here because we pass an empty string.
		panic(err)
	}

	// Reuse the general safe-browsing filter configuration with a new URL and
	// ID.
	c := b.conf.SafeBrowsing
	refrIvl := time.Duration(c.RefreshIvl)
	refrTimeout := time.Duration(c.RefreshTimeout)

	const id = filter.IDNewRegDomains

	hashPrefMtcs, err := metrics.NewHashPrefixFilter(
		b.mtrcNamespace,
		string(id),
		b.promRegisterer,
	)
	if err != nil {
		return fmt.Errorf("registering hashprefix filter metrics: %w", err)
	}

	prefix := path.Join(hashprefix.IDPrefix, string(id))

	b.newRegDomains, err = hashprefix.NewFilter(&hashprefix.FilterConfig{
		Logger:          b.baseLogger.With(slogutil.KeyPrefix, prefix),
		Cloner:          b.cloner,
		CacheManager:    b.cacheManager,
		Hashes:          b.newRegDomainsHashes,
		URL:             &b.env.NewRegDomainsURL.URL,
		ErrColl:         b.errColl,
		HashPrefixMtcs:  hashPrefMtcs,
		Metrics:         b.filterMtrc,
		ID:              id,
		CachePath:       filepath.Join(cacheDir, string(id)),
		ReplacementHost: c.BlockHost,
		Staleness:       refrIvl,
		RefreshTimeout:  refrTimeout,
		CacheTTL:        time.Duration(c.CacheTTL),
		CacheCount:      c.CacheSize,
		MaxSize:         maxSize,
	})
	if err != nil {
		return fmt.Errorf("creating filter: %w", err)
	}

	err = b.newRegDomains.RefreshInitial(ctx)
	if err != nil {
		return fmt.Errorf("initial refresh: %w", err)
	}

	refr := service.NewRefreshWorker(&service.RefreshWorkerConfig{
		// Note that we also set the same timeout for the http.Client in
		// [hashprefix.NewFilter].
		ContextConstructor: contextutil.NewTimeoutConstructor(refrTimeout),
		ErrorHandler:       newSlogErrorHandler(b.baseLogger, string(id)+"_refresh"),
		Refresher:          b.newRegDomains,
		Schedule:           timeutil.NewConstSchedule(refrIvl),
		RefreshOnShutdown:  false,
	})
	err = refr.Start(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("starting refresher: %w", err)
	}

	b.sigHdlr.AddService(refr)

	b.debugRefrs[prefix] = b.newRegDomains

	return nil
}

// initSafeBrowsing initializes the safe-browsing filter and hash storage.  It
// also adds the refresher with ID [hashprefix.IDPrefix]/[filter.IDSafeBrowsing]
// to the debug refreshers.
//
// It must be called from [builder.initHashPrefixFilters].
func (b *builder) initSafeBrowsing(
	ctx context.Context,
	matchers map[string]*hashprefix.Storage,
	maxSize datasize.ByteSize,
	cacheDir string,
) (err error) {
	if !b.env.SafeBrowsingEnabled {
		return nil
	}

	b.safeBrowsingHashes, err = hashprefix.NewStorage(nil)
	if err != nil {
		// Don't expect errors here because we pass an empty string.
		panic(err)
	}

	c := b.conf.SafeBrowsing
	refrIvl := time.Duration(c.RefreshIvl)
	refrTimeout := time.Duration(c.RefreshTimeout)

	const id = filter.IDSafeBrowsing

	hashPrefMtcs, err := metrics.NewHashPrefixFilter(
		b.mtrcNamespace,
		string(id),
		b.promRegisterer,
	)
	if err != nil {
		return fmt.Errorf("registering hashprefix filter metrics: %w", err)
	}

	prefix := path.Join(hashprefix.IDPrefix, string(id))

	b.safeBrowsing, err = hashprefix.NewFilter(&hashprefix.FilterConfig{
		Logger:          b.baseLogger.With(slogutil.KeyPrefix, prefix),
		Cloner:          b.cloner,
		CacheManager:    b.cacheManager,
		Hashes:          b.safeBrowsingHashes,
		URL:             &b.env.SafeBrowsingURL.URL,
		ErrColl:         b.errColl,
		HashPrefixMtcs:  hashPrefMtcs,
		Metrics:         b.filterMtrc,
		ID:              id,
		CachePath:       filepath.Join(cacheDir, string(id)),
		ReplacementHost: c.BlockHost,
		Staleness:       refrIvl,
		RefreshTimeout:  refrTimeout,
		CacheTTL:        time.Duration(c.CacheTTL),
		CacheCount:      c.CacheSize,
		MaxSize:         maxSize,
	})
	if err != nil {
		return fmt.Errorf("creating filter: %w", err)
	}

	err = b.safeBrowsing.RefreshInitial(ctx)
	if err != nil {
		return fmt.Errorf("initial refresh: %w", err)
	}

	refr := service.NewRefreshWorker(&service.RefreshWorkerConfig{
		// Note that we also set the same timeout for the http.Client in
		// [hashprefix.NewFilter].
		ContextConstructor: contextutil.NewTimeoutConstructor(refrTimeout),
		ErrorHandler:       newSlogErrorHandler(b.baseLogger, string(id)+"_refresh"),
		Refresher:          b.safeBrowsing,
		Schedule:           timeutil.NewConstSchedule(refrIvl),
		RefreshOnShutdown:  false,
	})
	err = refr.Start(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("starting refresher: %w", err)
	}

	b.sigHdlr.AddService(refr)

	matchers[filter.GeneralTXTSuffix] = b.safeBrowsingHashes

	b.debugRefrs[prefix] = b.safeBrowsing

	return nil
}

// initStandardAccess initializes the standard access settings.
//
// The following methods must be called before this one:
//   - [builder.initGRPCMetrics]
func (b *builder) initStandardAccess(ctx context.Context) (err error) {
	switch typ := b.env.StandardAccessType; typ {
	case standardAccessOff:
		b.standardAccess = access.EmptyBlocker{}

		return nil
	case standardAccessBackend:
		// Go on.
		//
		// TODO(e.burkov):  Extract the initialization logic to a separate
		// function.
	default:
		panic(fmt.Errorf("env STANDARD_ACCESS_TYPE: %w: %q", errors.ErrBadEnumValue, typ))
	}

	stdAcc := access.NewStandardBlocker(&access.StandardBlockerConfig{})
	b.standardAccess = stdAcc

	mtrc, err := metrics.NewBackendStandardAccess(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("initializing standard access metrics: %w", err)
	}

	strg, err := backendpb.NewStandardAccess(&backendpb.StandardAccessConfig{
		Endpoint:    &b.env.StandardAccessURL.URL,
		GRPCMetrics: b.backendGRPCMtrc,
		Metrics:     mtrc,
		Logger:      b.baseLogger.With(slogutil.KeyPrefix, "standard_access_storage"),
		ErrColl:     b.errColl,
		APIKey:      b.env.StandardAccessAPIKey,
	})
	if err != nil {
		return fmt.Errorf("initializing standard access storage: %w", err)
	}

	updater, err := filterstorage.NewStandardAccess(ctx, &filterstorage.StandardAccessConfig{
		BaseLogger: b.baseLogger,
		Logger:     b.baseLogger.With(slogutil.KeyPrefix, "standard_access_updater"),
		Getter:     strg,
		Setter:     stdAcc,
		CacheDir:   b.env.FilterCachePath,
	})
	if err != nil {
		return fmt.Errorf("initializing standard access updater: %w", err)
	}

	err = updater.Refresh(ctx)
	if err != nil {
		return fmt.Errorf("initializing standard access updater: %w", err)
	}

	refrWorker := service.NewRefreshWorker(&service.RefreshWorkerConfig{
		Clock: timeutil.SystemClock{},
		ContextConstructor: contextutil.NewTimeoutConstructor(
			time.Duration(b.env.StandardAccessTimeout),
		),
		ErrorHandler:      newSlogErrorHandler(b.baseLogger, "standard_access_refresh"),
		Refresher:         updater,
		Schedule:          timeutil.NewConstSchedule(time.Duration(b.env.StandardAccessRefreshIvl)),
		RefreshOnShutdown: false,
	})
	err = refrWorker.Start(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("starting standard access refresher: %w", err)
	}

	b.sigHdlr.AddService(refrWorker)

	b.debugRefrs[debugIDStandardProfileAccess] = updater

	return nil
}

// initFilterStorage initializes and refreshes the filter storage.  It also adds
// the refresher with ID [filter.StoragePrefix] to the debug refreshers.
//
// [builder.initHashPrefixFilters] must be called before this method.
func (b *builder) initFilterStorage(ctx context.Context) (err error) {
	c := b.conf.Filters
	refrIvl := time.Duration(c.RefreshIvl)
	refrTimeout := time.Duration(c.RefreshTimeout)

	var blockedSvcIdxURL *url.URL
	if b.env.BlockedServiceEnabled {
		blockedSvcIdxURL = &b.env.BlockedServiceIndexURL.URL
	}

	b.filterStorage, err = filterstorage.New(&filterstorage.Config{
		BaseLogger: b.baseLogger,
		Logger:     b.baseLogger.With(slogutil.KeyPrefix, filter.StoragePrefix),
		BlockedServices: &filterstorage.BlockedServicesConfig{
			IndexURL: blockedSvcIdxURL,
			// TODO(a.garipov):  Consider adding a separate parameter here.
			IndexMaxSize: c.MaxSize,
			// TODO(a.garipov):  Consider making configurable.
			IndexRefreshTimeout: 3 * time.Minute,
			// TODO(a.garipov):  Consider adding a separate parameter here.
			IndexStaleness: refrIvl,
			// TODO(a.garipov):  Consider adding a separate parameter here.
			ResultCacheCount: c.RuleListCache.Size,
			// TODO(a.garipov):  Consider adding a separate parameter here.
			ResultCacheEnabled: c.RuleListCache.Enabled,
			Enabled:            bool(b.env.BlockedServiceEnabled),
		},
		Custom: &filterstorage.CustomConfig{
			CacheCount: c.CustomFilterCacheSize,
		},
		HashPrefix: &filterstorage.HashPrefixConfig{
			Adult:           b.adultBlocking,
			Dangerous:       b.safeBrowsing,
			NewlyRegistered: b.newRegDomains,
		},
		RuleLists: &filterstorage.RuleListsConfig{
			IndexURL: &b.env.FilterIndexURL.URL,
			// TODO(a.garipov):  Consider adding a separate parameter here.
			IndexMaxSize:        c.MaxSize,
			MaxSize:             c.MaxSize,
			IndexRefreshTimeout: time.Duration(c.IndexRefreshTimeout),
			// TODO(a.garipov):  Consider adding a separate parameter here.
			IndexStaleness: refrIvl,
			RefreshTimeout: refrTimeout,
			// TODO(a.garipov):  Consider adding a separate parameter here.
			Staleness:          refrIvl,
			ResultCacheCount:   c.RuleListCache.Size,
			ResultCacheEnabled: c.RuleListCache.Enabled,
		},
		SafeSearchGeneral: b.newSafeSearchConfig(
			b.env.GeneralSafeSearchURL,
			filter.IDGeneralSafeSearch,
			bool(b.env.GeneralSafeSearchEnabled),
		),
		SafeSearchYouTube: b.newSafeSearchConfig(
			b.env.YoutubeSafeSearchURL,
			filter.IDYoutubeSafeSearch,
			bool(b.env.YoutubeSafeSearchEnabled),
		),
		CacheManager: b.cacheManager,
		Clock:        timeutil.SystemClock{},
		ErrColl:      b.errColl,
		Metrics:      b.filterMtrc,
		CacheDir:     b.env.FilterCachePath,
	})
	if err != nil {
		return fmt.Errorf("creating default filter storage: %w", err)
	}

	err = b.filterStorage.RefreshInitial(ctx)
	if err != nil {
		return fmt.Errorf("refreshing default filter storage: %w", err)
	}

	refr := service.NewRefreshWorker(&service.RefreshWorkerConfig{
		ContextConstructor: contextutil.NewTimeoutConstructor(refrTimeout),
		ErrorHandler:       newSlogErrorHandler(b.baseLogger, "filters/storage_refresh"),
		Refresher:          b.filterStorage,
		Schedule:           timeutil.NewConstSchedule(refrIvl),
		RefreshOnShutdown:  false,
	})
	err = refr.Start(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("starting default filter storage update: %w", err)
	}

	b.sigHdlr.AddService(refr)

	b.debugRefrs[filter.StoragePrefix] = b.filterStorage

	b.logger.DebugContext(ctx, "initialized filter storage")

	return nil
}

// newSafeSearchConfig returns a new safe-search configuration for the given URL
// and ID if enabled; otherwise, it returns an empty configuration.
func (b *builder) newSafeSearchConfig(
	u *urlutil.URL,
	id filter.ID,
	enabled bool,
) (c *filterstorage.SafeSearchConfig) {
	if !enabled {
		return &filterstorage.SafeSearchConfig{}
	}

	fltConf := b.conf.Filters

	return &filterstorage.SafeSearchConfig{
		URL: &u.URL,
		ID:  id,
		// TODO(a.garipov):  Consider adding a separate parameter here.
		MaxSize: fltConf.MaxSize,
		// TODO(a.garipov):  Consider making configurable.
		ResultCacheTTL: 1 * time.Hour,
		// TODO(a.garipov):  Consider adding a separate parameter here.
		RefreshTimeout: time.Duration(fltConf.RefreshTimeout),
		// TODO(a.garipov):  Consider adding a separate parameter here.
		Staleness:        time.Duration(fltConf.RefreshIvl),
		ResultCacheCount: fltConf.SafeSearchCacheSize,
		Enabled:          true,
	}
}

// initFilteringGroups initializes the filtering groups.
//
// [builder.initFilterStorage] must be called before this method.
func (b *builder) initFilteringGroups(ctx context.Context) (err error) {
	b.filteringGroups, err = b.conf.FilteringGroups.toInternal(b.filterStorage)
	if err != nil {
		return fmt.Errorf("initializing filtering groups: %w", err)
	}

	b.logger.DebugContext(ctx, "initialized filtering groups")

	return nil
}

// initAccess initializes the global access settings.
func (b *builder) initAccess(ctx context.Context) (err error) {
	c := b.conf.Access
	b.access, err = access.NewGlobal(
		c.BlockedQuestionDomains,
		netutil.UnembedPrefixes(c.BlockedClientSubnets),
	)
	if err != nil {
		return fmt.Errorf("initializing global access: %w", err)
	}

	b.logger.DebugContext(ctx, "initialized global access")

	return nil
}

// initBindToDevice initializes the bindtodevice feature manager.
func (b *builder) initBindToDevice(ctx context.Context) (err error) {
	c := b.conf

	mtrc, err := metrics.NewBindToDevice(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("registering bindtodevice metrics: %w", err)
	}

	var btdCtrlConf *bindtodevice.ControlConfig
	btdCtrlConf, b.controlConf = c.Network.toInternal()
	b.btdManager, err = c.InterfaceListeners.toInternal(b.baseLogger, b.errColl, mtrc, btdCtrlConf)
	if err != nil {
		return fmt.Errorf("converting interface listeners: %w", err)
	}

	b.logger.DebugContext(ctx, "initialized bindtodevice manager")

	return nil
}

// initDNSDB initializes the DNS database.
func (b *builder) initDNSDB(ctx context.Context) (err error) {
	if !b.conf.DNSDB.Enabled {
		b.dnsDB = dnsdb.Empty{}

		return nil
	}

	mtrc, err := metrics.NewDNSDB(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("registering dnsdb metrics: %w", err)
	}

	b.dnsDB = dnsdb.New(&dnsdb.DefaultConfig{
		Logger:  b.baseLogger.With(slogutil.KeyPrefix, "dnsdb"),
		ErrColl: b.errColl,
		Metrics: mtrc,
		MaxSize: b.conf.DNSDB.MaxSize,
	})

	b.logger.DebugContext(ctx, "initialized dns database")

	return nil
}

// initQueryLog initializes the appropriate query log implementation from the
// configuration and environment data.
func (b *builder) initQueryLog(ctx context.Context) (err error) {
	if !b.conf.QueryLog.File.Enabled {
		b.queryLog = querylog.Empty{}

		b.logger.DebugContext(ctx, "initialized empty query log")

		return nil
	}

	mtrc, err := metrics.NewQueryLog(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("registering querylog metrics: %w", err)
	}

	var sema syncutil.Semaphore
	if b.env.QueryLogSemaphoreEnabled {
		sema = syncutil.NewChanSemaphore(b.env.QueryLogSemaphoreLimit)
	} else {
		sema = syncutil.EmptySemaphore{}
	}

	b.queryLog = querylog.NewFileSystem(&querylog.FileSystemConfig{
		Logger:    b.baseLogger.With(slogutil.KeyPrefix, "querylog"),
		Path:      b.env.QueryLogPath,
		Metrics:   mtrc,
		Semaphore: sema,
		RandSeed:  randutil.MustNewSeed(),
	})

	b.logger.DebugContext(ctx, "initialized file-based query log")

	return nil
}

// Constants for the experimental Structured DNS Errors feature.
//
// TODO(a.garipov):  Make configurable.
const (
	sdeJustification = "Filtered by AdGuard DNS"
	sdeOrganization  = "AdGuard DNS"
)

// Variables for the experimental Structured DNS Errors feature.
//
// TODO(a.garipov):  Make configurable.
var (
	sdeContactURL = &url.URL{
		Scheme: "mailto",
		Opaque: "support@adguard-dns.io",
	}
)

// initMsgConstructor initializes the common DNS message constructor.
//
// [builder.initMsgCloner] must be called before this method.
func (b *builder) initMsgConstructor(ctx context.Context) (err error) {
	fltConf := b.conf.Filters
	b.sdeConf = &dnsmsg.StructuredDNSErrorsConfig{
		Contact: []*url.URL{
			sdeContactURL,
		},
		Justification: sdeJustification,
		Organization:  sdeOrganization,
		Enabled:       fltConf.SDEEnabled,
	}

	b.messages, err = dnsmsg.NewConstructor(&dnsmsg.ConstructorConfig{
		Cloner:              b.cloner,
		BlockingMode:        &dnsmsg.BlockingModeNullIP{},
		StructuredErrors:    b.sdeConf,
		FilteredResponseTTL: time.Duration(fltConf.ResponseTTL),
		EDEEnabled:          fltConf.EDEEnabled,
	})
	if err != nil {
		return fmt.Errorf("creating dns message constructor: %w", err)
	}

	b.logger.DebugContext(ctx, "initialized dns message constructor")

	return nil
}

// initTLSManager initializes the TLS manager and the TLS-related metrics.  It
// also adds the refresher with ID [debugIDTLSConfig] to the debug refreshers.
//
// [builder.initGRPCMetrics] must be called before this method.
func (b *builder) initTLSManager(ctx context.Context) (err error) {
	mtrc, err := metrics.NewTLSConfigManager(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("registering tls metrics: %w", err)
	}

	tickDB, err := b.newTicketDB(ctx)
	if err != nil {
		return fmt.Errorf("creating ticket refresher: %w", err)
	}

	logFile := b.env.SSLKeyLogFile
	if logFile != "" {
		b.logger.WarnContext(ctx, "tls key logging is enabled", "file", logFile)
	}

	mgr, err := tlsconfig.NewDefaultManager(&tlsconfig.DefaultManagerConfig{
		Logger:         b.baseLogger.With(slogutil.KeyPrefix, "tlsconfig"),
		ErrColl:        b.errColl,
		Metrics:        mtrc,
		TicketDB:       tickDB,
		KeyLogFilename: logFile,
	})
	if err != nil {
		return fmt.Errorf("initializing tls manager: %w", err)
	}

	b.tlsManager = mgr
	b.debugRefrs[debugIDTLSConfig] = mgr

	b.logger.DebugContext(ctx, "initialized tls manager")

	return nil
}

// newTicketDB creates a new session ticket database depending on the session
// ticket type.
func (b *builder) newTicketDB(ctx context.Context) (db tlsconfig.TicketDB, err error) {
	switch typ := b.env.SessionTicketType; typ {
	case sessionTicketLocal:
		b.logger.InfoContext(ctx, "using local session tickets storage")

		ticketPaths := b.conf.ServerGroups.collectSessTicketPaths()
		db = tlsconfig.NewLocalTicketDB(&tlsconfig.LocalTicketDBConfig{
			Paths: ticketPaths,
		})
	case sessionTicketRemote:
		b.logger.InfoContext(ctx, "using remote session tickets storage")

		var mtrc backendpb.TicketStorageMetrics
		mtrc, err = metrics.NewBackendTicketStorage(b.mtrcNamespace, b.promRegisterer)
		if err != nil {
			return nil, fmt.Errorf("registering session ticket storage metrics: %w", err)
		}

		var strg *backendpb.TicketStorage
		strg, err = backendpb.NewSessionTicketStorage(&backendpb.TicketStorageConfig{
			Logger:      b.baseLogger.With(slogutil.KeyPrefix, "ticket storage"),
			Endpoint:    &b.env.SessionTicketURL.URL,
			GRPCMetrics: b.backendGRPCMtrc,
			Metrics:     mtrc,
			Clock:       timeutil.SystemClock{},
			APIKey:      b.env.SessionTicketAPIKey,
		})
		if err != nil {
			return nil, fmt.Errorf("creating remote session ticket storage: %w", err)
		}

		db, err = tlsconfig.NewRemoteTicketDB(&tlsconfig.RemoteTicketDBConfig{
			Logger:        b.baseLogger.With(slogutil.KeyPrefix, "ticket database"),
			Storage:       strg,
			Clock:         timeutil.SystemClock{},
			CacheDirPath:  b.env.SessionTicketCachePath,
			IndexFileName: b.env.SessionTicketIndexName,
		})
		if err != nil {
			return nil, fmt.Errorf("creating session ticket database: %w", err)
		}
	default:
		panic(fmt.Errorf("env SESSION_TICKET_TYPE: %w: %q", errors.ErrBadEnumValue, typ))
	}

	return db, nil
}

// initCustomDomainDB initializes the database for the custom domains.
//
// [builder.initTLSManager] must be called before this method.
func (b *builder) initCustomDomainDB(ctx context.Context) (err error) {
	if !bool(b.env.CustomDomainsEnabled) || !b.profilesEnabled {
		b.logger.WarnContext(ctx, "custom domains are disabled")

		b.dnsSvcCustomDomainDB = dnssvc.EmptyCustomDomainDB{}
		b.profDBCustomDomainDB = profiledb.EmptyCustomDomainDB{}
		b.webSvcCertValidator = websvc.RejectCertificateValidator{}

		return nil
	}

	strgMtrc, err := metrics.NewBackendCustomDomainStorage(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("registering custom domain storage metrics: %w", err)
	}

	strg, err := backendpb.NewCustomDomainStorage(&backendpb.CustomDomainStorageConfig{
		Endpoint:    &b.env.CustomDomainsURL.URL,
		Logger:      b.baseLogger.With(slogutil.KeyPrefix, "custom_domain_storage"),
		Clock:       timeutil.SystemClock{},
		GRPCMetrics: b.backendGRPCMtrc,
		Metrics:     strgMtrc,
		APIKey:      b.env.CustomDomainsAPIKey,
	})
	if err != nil {
		return fmt.Errorf("custom domain storage: %w", err)
	}

	mtrc, err := metrics.NewCustomDomainDB(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("registering custom domain database metrics: %w", err)
	}

	b.customDomainDB, err = tlsconfig.NewCustomDomainDB(&tlsconfig.CustomDomainDBConfig{
		Logger:          b.baseLogger.With(slogutil.KeyPrefix, "custom_domain_db"),
		Clock:           timeutil.SystemClock{},
		ErrColl:         b.errColl,
		Manager:         b.tlsManager,
		Metrics:         mtrc,
		Storage:         strg,
		CacheDirPath:    b.env.CustomDomainsCachePath,
		InitialRetryIvl: time.Duration(b.env.CustomDomainsRefreshIvl),
		// TODO(a.garipov): Consider making configurable.
		MaxRetryIvl: 1 * timeutil.Day,
	})
	if err != nil {
		return fmt.Errorf("custom domain db: %w", err)
	}

	b.dnsSvcCustomDomainDB = b.customDomainDB
	b.profDBCustomDomainDB = b.customDomainDB
	b.webSvcCertValidator = b.customDomainDB

	// NOTE:  The initial refresh and thus full initialization is done in
	// [builder.refreshCustomDomainDB].

	b.logger.DebugContext(ctx, "prepared custom domain db")

	return nil
}

// initServerGroups initializes the server groups.
//
// The following methods must be called before this one:
//   - [builder.initBindToDevice]
//   - [builder.initFilteringGroups]
//   - [builder.initMsgConstructor]
//   - [builder.initTLSManager]
func (b *builder) initServerGroups(ctx context.Context) (err error) {
	c := b.conf
	b.serverGroups, err = c.ServerGroups.toInternal(
		ctx,
		b.messages,
		b.btdManager,
		b.tlsManager,
		b.filteringGroups,
		c.RateLimit,
		c.DNS,
	)
	if err != nil {
		return fmt.Errorf("initializing server groups: %w", err)
	}

	b.setServerGroupProperties(ctx)

	b.logger.DebugContext(ctx, "initialized server groups")

	return nil
}

// initTicketRotator initializes the TLS session ticket rotator.  It also adds
// the refresher with ID [debugIDTicketRotator] to the debug refreshers.
//
// [builder.initServerGroups] must be called before this method.
func (b *builder) initTicketRotator(ctx context.Context) (err error) {
	tickRot := service.RefresherFunc(b.tlsManager.RotateTickets)

	err = tickRot.Refresh(ctx)
	if err != nil {
		return fmt.Errorf("initial session ticket refresh: %w", err)
	}

	refr := service.NewRefreshWorker(&service.RefreshWorkerConfig{
		ContextConstructor: contextutil.NewTimeoutConstructor(defaultTimeout),
		ErrorHandler:       newSlogErrorHandler(b.baseLogger, "tickrot_refresh"),
		Refresher:          tickRot,
		Schedule:           timeutil.NewConstSchedule(time.Duration(b.env.SessionTicketRefreshIvl)),
		RefreshOnShutdown:  false,
	})
	err = refr.Start(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("starting ticket rotator refresh: %w", err)
	}

	b.sigHdlr.AddService(refr)

	b.debugRefrs[debugIDTicketRotator] = tickRot

	b.logger.DebugContext(ctx, "initialized tls")

	return nil
}

// setServerGroupProperties sets b.profilesEnabled and b.bindSet depending on
// the server-group data.
func (b *builder) setServerGroupProperties(ctx context.Context) {
	var serverPrefixes []netip.Prefix
	allSingleIP := true
	for _, grp := range b.serverGroups {
		for _, srv := range grp.Servers {
			for _, p := range srv.BindDataPrefixes() {
				allSingleIP = allSingleIP && p.IsSingleIP()
				serverPrefixes = append(serverPrefixes, p)
			}
		}
	}

	if !b.profilesEnabled {
		b.logger.WarnContext(ctx, "profiles are disabled for all server groups")
	}

	if !allSingleIP {
		b.bindSet = netutil.SliceSubnetSet(serverPrefixes)

		return
	}

	b.logger.WarnContext(ctx, "all bind ifaces are single-ip; only checking validity of ips")

	// In cases where an installation only has single-IP prefixes in bind
	// interfaces, or no bind interfaces at all, only check the dedicated IPs in
	// profiles for validity.
	//
	// TODO(a.garipov):  Add an explicit env flag for this.
	b.bindSet = netutil.SubnetSetFunc(netip.Addr.IsValid)
}

// startBindToDevice starts the bindtodevice manager and registers it in the
// signal handler.
//
// The following methods must be called before this one:
//   - [builder.initBindToDevice]
//   - [builder.initFilteringGroups]
//   - [builder.initServerGroups]
func (b *builder) startBindToDevice(ctx context.Context) (err error) {
	// Start the bind-to-device manager here, now that no further calls to
	// b.btdManager.ListenConfig are required.
	err = b.btdManager.Start(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("starting bindtodevice manager: %w", err)
	}

	b.sigHdlr.AddService(b.btdManager)

	b.logger.DebugContext(ctx, "started bindtodevice manager")

	return nil
}

// defaultTimeout is the timeout used for some operations where another timeout
// hasn't been defined yet.
const defaultTimeout = 30 * time.Second

// initGRPCMetrics initializes the gRPC metrics if necessary.
func (b *builder) initGRPCMetrics(ctx context.Context) (err error) {
	b.backendGRPCMtrc = b.plugins.GRPCMetrics()

	switch {
	case b.backendGRPCMtrc != nil:
		b.logger.DebugContext(ctx, "initialized grpc metrics from plugin")

		return nil
	case
		b.profilesEnabled,
		b.env.SessionTicketType == sessionTicketRemote,
		b.env.StandardAccessType == standardAccessBackend,
		b.env.DNSCheckKVType == kvModeBackend,
		b.env.RateLimitAllowlistType == rlAllowlistTypeBackend:
		// Go on.
	default:
		// Don't initialize the metrics if no protobuf backend is used.
		return nil
	}

	b.backendGRPCMtrc, err = metrics.NewBackendGRPC(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("registering backend grpc metrics: %w", err)
	}

	b.logger.DebugContext(ctx, "initialized backend grpc metrics")

	return nil
}

// initBillStat initializes the billing-statistics recorder if necessary.  It
// also adds the refresher with ID [debugIDBillStat] to the debug refreshers.
// [builder.initGRPCMetrics] must be called before this method.
func (b *builder) initBillStat(ctx context.Context) (err error) {
	if !b.profilesEnabled {
		b.billStat = billstat.EmptyRecorder{}

		return nil
	}

	upl, err := b.newBillStatUploader()
	if err != nil {
		return fmt.Errorf("creating billstat uploader: %w", err)
	}

	mtrc, err := metrics.NewBillstat(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("registering billstat metrics: %w", err)
	}

	billStat := billstat.NewRuntimeRecorder(&billstat.RuntimeRecorderConfig{
		Logger:   b.baseLogger.With(slogutil.KeyPrefix, "billstat"),
		ErrColl:  b.errColl,
		Uploader: upl,
		Metrics:  mtrc,
	})

	c := b.conf.Backend
	refrIvl := time.Duration(c.BillStatIvl)
	timeout := time.Duration(c.Timeout)

	b.billStat = billStat
	refr := service.NewRefreshWorker(&service.RefreshWorkerConfig{
		ContextConstructor: contextutil.NewTimeoutConstructor(timeout),
		ErrorHandler:       newSlogErrorHandler(b.baseLogger, "billstat_refresh"),
		Refresher:          billStat,
		Schedule:           timeutil.NewConstSchedule(refrIvl),
		RefreshOnShutdown:  true,
	})
	err = refr.Start(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("starting billstat recorder refresher: %w", err)
	}

	b.sigHdlr.AddService(refr)

	b.debugRefrs[debugIDBillStat] = billStat

	b.logger.DebugContext(ctx, "initialized billstat")

	return nil
}

// newBillStatUploader creates and returns a billstat uploader depending on the
// provided API URL.
func (b *builder) newBillStatUploader() (s billstat.Uploader, err error) {
	apiURL := netutil.CloneURL(&b.env.BillStatURL.URL)
	err = urlutil.ValidateGRPCURL(apiURL)
	if err != nil {
		return nil, fmt.Errorf("billstat api url: %w", err)
	}

	return backendpb.NewBillStat(&backendpb.BillStatConfig{
		Logger:      b.baseLogger.With(slogutil.KeyPrefix, "billstat_uploader"),
		ErrColl:     b.errColl,
		GRPCMetrics: b.backendGRPCMtrc,
		Endpoint:    apiURL,
		APIKey:      b.env.BillStatAPIKey,
	})
}

// initProfileDB initializes the profile database if necessary.  It also adds
// the refreshers with ID [debugIDProfileDB], [debugIDProfileDBFull] to the
// debug refreshers.
//
// The following methods must be called before this one:
//   - [builder.initCustomDomainDB]
//   - [builder.initGRPCMetrics]
func (b *builder) initProfileDB(ctx context.Context) (err error) {
	if !b.profilesEnabled {
		b.profileDB = &profiledb.Disabled{}

		return nil
	}

	apiURL := netutil.CloneURL(&b.env.ProfilesURL.URL)
	err = urlutil.ValidateGRPCURL(apiURL)
	if err != nil {
		return fmt.Errorf("profile api url: %w", err)
	}

	profileMtrc, err := metrics.NewAccessProfile(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("registering profile access engine metrics: %w", err)
	}

	profAccessCons := access.NewProfileConstructor(&access.ProfileConstructorConfig{
		Metrics:  profileMtrc,
		Standard: b.standardAccess,
	})

	backendProfileDBMtrc, err := metrics.NewBackendProfileDB(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("registering backend grpc profile metrics: %w", err)
	}

	respSzEst := b.conf.RateLimit.ResponseSizeEstimate
	customLogger := b.baseLogger.With(slogutil.KeyPrefix, "filters/"+string(filter.IDCustom))
	strg, err := backendpb.NewProfileStorage(&backendpb.ProfileStorageConfig{
		Logger:                   b.baseLogger.With(slogutil.KeyPrefix, "profilestorage"),
		BaseCustomLogger:         customLogger,
		Endpoint:                 apiURL,
		ProfileAccessConstructor: profAccessCons,
		BindSet:                  b.bindSet,
		ErrColl:                  b.errColl,
		GRPCMetrics:              b.backendGRPCMtrc,
		Metrics:                  backendProfileDBMtrc,
		APIKey:                   b.env.ProfilesAPIKey,
		ResponseSizeEstimate:     respSzEst,
		MaxProfilesSize:          b.env.ProfilesMaxRespSize,
	})
	if err != nil {
		return fmt.Errorf("creating profile storage: %w", err)
	}

	profDBMtrc, err := metrics.NewProfileDB(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("registering profile database metrics: %w", err)
	}

	c := b.conf.Backend
	timeout := time.Duration(c.Timeout)
	profDB, err := profiledb.New(&profiledb.Config{
		Logger:                   b.baseLogger.With(slogutil.KeyPrefix, "profiledb"),
		BaseCustomLogger:         customLogger,
		ProfileAccessConstructor: profAccessCons,
		Clock:                    timeutil.SystemClock{},
		CustomDomainDB:           b.profDBCustomDomainDB,
		ErrColl:                  b.errColl,
		ProfileMetrics:           profileMtrc,
		Metrics:                  profDBMtrc,
		Storage:                  strg,
		CacheFilePath:            b.env.ProfilesCachePath,
		FullSyncIvl:              time.Duration(c.FullRefreshIvl),
		FullSyncRetryIvl:         time.Duration(c.FullRefreshRetryIvl),
		ResponseSizeEstimate:     respSzEst,
	})
	if err != nil {
		return fmt.Errorf("creating default profile database: %w", err)
	}

	err = initProfDB(ctx, b.logger, profDB, timeout)
	if err != nil {
		return fmt.Errorf("preparing default profile database: %w", err)
	}

	b.profileDB = profDB

	// Randomize the start of the profile DB refresh by up to 10 % to not
	// overload the profile storage.
	refrIvl := time.Duration(c.RefreshIvl)
	sched := timeutil.NewRandomizedSchedule(
		timeutil.NewConstSchedule(refrIvl),
		b.rand,
		0,
		refrIvl/10,
	)
	refr := service.NewRefreshWorker(&service.RefreshWorkerConfig{
		ContextConstructor: contextutil.NewTimeoutConstructor(timeout),
		ErrorHandler:       newSlogErrorHandler(b.baseLogger, "profiledb_refresh"),
		Refresher:          profDB,
		Schedule:           sched,
		RefreshOnShutdown:  false,
	})
	err = refr.Start(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("starting default profile database refresher: %w", err)
	}

	b.sigHdlr.AddService(refr)

	b.debugRefrs[debugIDProfileDB] = profDB

	profRefr := service.RefresherFunc(profDB.RefreshFull)
	b.debugRefrs[debugIDProfileDBFull] = profRefr

	b.logger.DebugContext(ctx, "initialized profiledb")

	return nil
}

// refreshCustomDomainDB performs the initial refresh of the custom-domain
// database.
//
// [builder.initProfileDB] must be called before this method.
func (b *builder) refreshCustomDomainDB(ctx context.Context) (err error) {
	if !bool(b.env.CustomDomainsEnabled) || !b.profilesEnabled {
		return nil
	}

	err = b.customDomainDB.Refresh(ctx)
	if err != nil {
		return fmt.Errorf("custom domain db: initial refresh: %w", err)
	}

	refr := service.NewRefreshWorker(&service.RefreshWorkerConfig{
		// TODO(a.garipov):  Consider making configurable.
		ContextConstructor: contextutil.NewTimeoutConstructor(defaultTimeout),
		Refresher:          b.customDomainDB,
		Schedule:           timeutil.NewConstSchedule(time.Duration(b.env.CustomDomainsRefreshIvl)),
	})

	err = refr.Start(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("starting custom domain db refresher: %w", err)
	}

	b.sigHdlr.AddService(refr)

	b.debugRefrs[debugIDCustomDomainDB] = b.customDomainDB

	b.logger.DebugContext(ctx, "initialized custom domain db")

	return nil
}

// initDNSCheck initializes the DNS checker.
//
// [builder.initGRPCMetrics] and [builder.initMsgConstructor] must be called
// before this method.
func (b *builder) initDNSCheck(ctx context.Context) (err error) {
	b.dnsCheck = b.plugins.DNSCheck()
	if b.dnsCheck != nil {
		b.logger.DebugContext(ctx, "initialized dnscheck from plugin")

		return nil
	}

	c := b.conf.Check

	checkConf, err := c.toInternal(
		ctx,
		b.baseLogger,
		b.env,
		b.messages,
		b.errColl,
		b.mtrcNamespace,
		b.promRegisterer,
		b.backendGRPCMtrc,
	)
	if err != nil {
		return fmt.Errorf("initializing dnscheck: %w", err)
	}

	b.dnsCheck = dnscheck.NewRemoteKV(checkConf)

	b.logger.DebugContext(ctx, "initialized dnscheck")

	return nil
}

// initRuleStat initializes the rule statistics.  It also adds the refresher
// with ID [debugIDRuleStat] to the debug refreshers.
func (b *builder) initRuleStat(ctx context.Context) (err error) {
	b.ruleStat = b.plugins.RuleStat()
	if b.ruleStat != nil {
		b.logger.DebugContext(ctx, "initialized rulestat from plugin")

		return nil
	}

	u := b.env.RuleStatURL
	if u == nil {
		b.logger.WarnContext(ctx, "not collecting rule statistics")

		b.ruleStat = rulestat.Empty{}

		return nil
	}

	mtrc, err := metrics.NewRuleStat(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("rulestat metrics: %w", err)
	}

	ruleStat := rulestat.NewHTTP(&rulestat.HTTPConfig{
		Logger:  b.baseLogger.With(slogutil.KeyPrefix, "rulestat"),
		ErrColl: b.errColl,
		Metrics: mtrc,
		URL:     &u.URL,
	})

	b.ruleStat = ruleStat
	refr := service.NewRefreshWorker(&service.RefreshWorkerConfig{
		ContextConstructor: contextutil.NewTimeoutConstructor(defaultTimeout),
		ErrorHandler:       newSlogErrorHandler(b.baseLogger, "rulestat_refresh"),
		Refresher:          ruleStat,
		// TODO(a.garipov):  Make configurable.
		Schedule:          timeutil.NewConstSchedule(10 * time.Minute),
		RefreshOnShutdown: true,
	})
	err = refr.Start(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("starting rulestat refresher: %w", err)
	}

	b.sigHdlr.AddService(refr)

	b.debugRefrs[debugIDRuleStat] = ruleStat

	b.logger.DebugContext(ctx, "initialized rulestat")

	return nil
}

// initRateLimiter initializes the rate limiter and the connection limiter as
// well as starts and registers the rate-limiter refresher in the signal
// handler.  It also adds the refresher with ID [debugIDAllowlist] to the debug
// refreshers.
//
// [builder.initGRPCMetrics] must be called before this method.
func (b *builder) initRateLimiter(ctx context.Context) (err error) {
	c := b.conf.RateLimit
	allowSubnets := netutil.UnembedPrefixes(c.Allowlist.List)
	allowlist := ratelimit.NewDynamicAllowlist(allowSubnets, nil)

	typ := b.env.RateLimitAllowlistType
	mtrc, err := metrics.NewAllowlist(b.mtrcNamespace, b.promRegisterer, typ)
	if err != nil {
		return fmt.Errorf("ratelimit metrics: %w", err)
	}

	var updater service.Refresher
	if typ == rlAllowlistTypeBackend {
		updater, err = backendpb.NewRateLimiter(&backendpb.RateLimiterConfig{
			Logger:      b.baseLogger.With(slogutil.KeyPrefix, "backend_ratelimiter"),
			Metrics:     mtrc,
			GRPCMetrics: b.backendGRPCMtrc,
			Allowlist:   allowlist,
			Endpoint:    &b.env.BackendRateLimitURL.URL,
			ErrColl:     b.errColl,
			APIKey:      b.env.BackendRateLimitAPIKey,
		})
		if err != nil {
			return fmt.Errorf("ratelimit: %w", err)
		}
	} else {
		updater = consul.NewAllowlistUpdater(&consul.AllowlistUpdaterConfig{
			Logger:    b.baseLogger.With(slogutil.KeyPrefix, "ratelimit_allowlist_updater"),
			Allowlist: allowlist,
			ConsulURL: &b.env.ConsulAllowlistURL.URL,
			ErrColl:   b.errColl,
			Metrics:   mtrc,
			// TODO(a.garipov):  Make configurable.
			Timeout: 15 * time.Second,
		})
	}

	err = updater.Refresh(ctx)
	if err != nil {
		return fmt.Errorf("allowlist: initial refresh: %w", err)
	}

	refr := service.NewRefreshWorker(&service.RefreshWorkerConfig{
		ContextConstructor: contextutil.NewTimeoutConstructor(defaultTimeout),
		ErrorHandler:       newSlogErrorHandler(b.baseLogger, "ratelimit_allowlist_refresh"),
		Refresher:          updater,
		Schedule:           timeutil.NewConstSchedule(time.Duration(c.Allowlist.RefreshIvl)),
		RefreshOnShutdown:  false,
	})
	err = refr.Start(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("starting allowlist refresher: %w", err)
	}

	b.sigHdlr.AddService(refr)

	err = b.initConnLimit(ctx, c.ConnectionLimit)
	if err != nil {
		return fmt.Errorf("connlimit: %w", err)
	}

	b.rateLimit = ratelimit.NewBackoff(c.toInternal(allowlist))

	b.debugRefrs[debugIDAllowlist] = updater

	b.logger.DebugContext(ctx, "initialized ratelimit")

	return nil
}

// initConnLimit initializes the connection limiter from the given conf.
func (b *builder) initConnLimit(ctx context.Context, conf *connLimitConfig) (err error) {
	if !conf.Enabled {
		return nil
	}

	mtrc, err := metrics.NewConnLimiter(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("metrics: %w", err)
	}

	b.connLimit = connlimiter.New(conf.toInternal(ctx, b.baseLogger, mtrc))

	return nil
}

// initWeb initializes the web service, starts it, and registers it in the
// signal handler.
//
// The following methods must be called before this one:
//   - [builder.initDNSCheck]
//   - [builder.initProfileDB]
func (b *builder) initWeb(ctx context.Context) (err error) {
	webSvcMtrc, err := metrics.NewWebSvc(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("initializing web service: %w", err)
	}

	c := b.conf.Web
	webConf, err := c.toInternal(
		ctx,
		b.env,
		b.dnsCheck,
		b.errColl,
		b.baseLogger,
		b.tlsManager,
		webSvcMtrc,
	)
	if err != nil {
		return fmt.Errorf("converting web configuration: %w", err)
	}

	webConf.CertificateValidator = b.webSvcCertValidator

	b.webSvc = websvc.New(webConf)

	err = b.webSvc.Refresh(ctx)
	if err != nil {
		return fmt.Errorf("web: initial refresh: %w", err)
	}

	refr := service.NewRefreshWorker(&service.RefreshWorkerConfig{
		ContextConstructor: contextutil.NewTimeoutConstructor(defaultTimeout),
		ErrorHandler:       newSlogErrorHandler(b.baseLogger, "websvc_refresh"),
		Refresher:          b.webSvc,
		// TODO(a.garipov): Consider making configurable.
		Schedule:          timeutil.NewConstSchedule(5 * time.Minute),
		RefreshOnShutdown: false,
	})
	err = refr.Start(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("starting websvc refresher: %w", err)
	}

	b.sigHdlr.AddService(refr)

	// The web service is considered critical, so its Start method panics
	// instead of returning an error.
	_ = b.webSvc.Start(context.WithoutCancel(ctx))

	b.sigHdlr.AddService(b.webSvc)

	b.debugRefrs[debugIDWebSvc] = b.webSvc

	b.logger.DebugContext(ctx, "initialized web")

	return nil
}

// waitGeoIP waits for the GeoIP initialization and registers its refresher.  It
// also adds the refresher with ID [debugIDGeoIP] to the debug refreshers.
func (b *builder) waitGeoIP(ctx context.Context) (err error) {
	err = <-b.geoIPError
	if err != nil {
		return fmt.Errorf("geoip: %w", err)
	}

	const prefix = "geoip_refresh"
	refrLogger := b.baseLogger.With(slogutil.KeyPrefix, prefix)
	refr := service.NewRefreshWorker(&service.RefreshWorkerConfig{
		ContextConstructor: contextutil.NewTimeoutConstructor(defaultTimeout),
		// Do not add errColl to geoip's config, as that would create an import
		// cycle.
		//
		// TODO(a.garipov):  Resolve that.
		ErrorHandler:      errcoll.NewRefreshErrorHandler(refrLogger, b.errColl),
		Refresher:         b.geoIP,
		Schedule:          timeutil.NewConstSchedule(time.Duration(b.conf.GeoIP.RefreshIvl)),
		RefreshOnShutdown: false,
	})
	err = refr.Start(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("starting geoip refresher: %w", err)
	}

	b.sigHdlr.AddService(refr)

	b.debugRefrs[debugIDGeoIP] = b.geoIP

	return nil
}

// initDNS initializes the DNS service.
//
// The following methods must be called before this one:
//   - [builder.initAccess]
//   - [builder.initBillStat]
//   - [builder.initBindToDevice]
//   - [builder.initCustomDomainDB]
//   - [builder.initDNSDB]
//   - [builder.initFilterStorage]
//   - [builder.initFilteringGroups]
//   - [builder.initMsgCloner]
//   - [builder.initMsgConstructor]
//   - [builder.initProfileDB]
//   - [builder.initQueryLog]
//   - [builder.initRateLimiter]
//   - [builder.initRuleStat]
//   - [builder.initWeb]
//   - [builder.waitGeoIP]
func (b *builder) initDNS(ctx context.Context) (err error) {
	mtrcListener, err := dnssvcprom.NewForwardMetricsListener(
		b.mtrcNamespace,
		b.promRegisterer,
		len(b.conf.Upstream.Servers)+len(b.conf.Upstream.Fallback.Servers),
	)
	if err != nil {
		return fmt.Errorf("forward metrics listener: %w", err)
	}

	b.fwdHandler = forward.NewHandler(b.conf.Upstream.toInternal(b.baseLogger, mtrcListener))

	dnsHdlrsConf := &dnssvc.HandlersConfig{
		BaseLogger:            b.baseLogger,
		Cache:                 b.conf.Cache.toInternal(),
		Cloner:                b.cloner,
		HumanIDParser:         agd.NewHumanIDParser(),
		MainMiddlewareMetrics: b.plugins.MainMiddlewareMetrics(),
		Messages:              b.messages,
		PostInitialMiddleware: b.plugins.PostInitialMiddleware(),
		StructuredErrors:      b.sdeConf,
		AccessManager:         b.access,
		BillStat:              b.billStat,
		CacheManager:          b.cacheManager,
		CustomDomainDB:        b.dnsSvcCustomDomainDB,
		DNSCheck:              b.dnsCheck,
		DNSDB:                 b.dnsDB,
		ErrColl:               b.errColl,
		FilterStorage:         b.filterStorage,
		GeoIP:                 b.geoIP,
		Handler:               b.fwdHandler,
		HashMatcher:           b.hashMatcher,
		ProfileDB:             b.profileDB,
		PrometheusRegisterer:  b.promRegisterer,
		QueryLog:              b.queryLog,
		RateLimit:             b.rateLimit,
		RuleStat:              b.ruleStat,
		MetricsNamespace:      b.mtrcNamespace,
		NodeName:              b.env.NodeName,
		FilteringGroups:       b.filteringGroups,
		ServerGroups:          b.serverGroups,
		EDEEnabled:            b.conf.Filters.EDEEnabled,
	}

	dnsHdlrs, err := dnssvc.NewHandlers(ctx, dnsHdlrsConf)
	if err != nil {
		return fmt.Errorf("dns handlers: %w", err)
	}

	dnsConf := &dnssvc.Config{
		BaseLogger:           b.baseLogger,
		Handlers:             dnsHdlrs,
		Cloner:               b.cloner,
		ControlConf:          b.controlConf,
		ConnLimiter:          b.connLimit,
		NonDNS:               b.webSvc.Handler(),
		ErrColl:              b.errColl,
		PrometheusRegisterer: b.promRegisterer,
		MetricsNamespace:     b.mtrcNamespace,
		ServerGroups:         b.serverGroups,
		HandleTimeout:        time.Duration(b.conf.DNS.HandleTimeout),
	}

	b.dnsSvc, err = dnssvc.New(dnsConf)
	if err != nil {
		return fmt.Errorf("dns service: %w", err)
	}

	b.logger.DebugContext(ctx, "initialized dns")

	return nil
}

// performConnCheck performs the connectivity check in accordance to the
// configuration given so far.
//
// [builder.initServerGroups] must be called before this method.
func (b *builder) performConnCheck(ctx context.Context) (err error) {
	err = connectivityCheck(b.serverGroups, b.conf.ConnectivityCheck)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	b.logger.DebugContext(ctx, "connectivity check success")

	return nil
}

// initHealthCheck initializes and registers the healthcheck worker.
//
// [builder.initDNS] must be called before this method.
func (b *builder) initHealthCheck(ctx context.Context) (err error) {
	upd := newUpstreamHealthcheck(b.baseLogger, b.fwdHandler, b.conf.Upstream, b.errColl)
	err = upd.Start(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("initializing healthcheck: %w", err)
	}

	b.sigHdlr.AddService(upd)

	b.logger.DebugContext(ctx, "initialized healthcheck")

	return nil
}

// initPluginRefreshers initializes plugin refresher workers.  It adds each
// refresher to builder's debug refreshers.
func (b *builder) initPluginRefreshers() {
	for id, r := range b.plugins.Refreshers() {
		b.debugRefrs[debugIDPrefixPlugin+id] = r
	}
}

// initPluginServices initializes plugin services.  It starts each service and
// adds them to the signal handler.
func (b *builder) initPluginServices(ctx context.Context) (err error) {
	var errs []error
	for id, svc := range b.plugins.Services() {
		err = svc.Start(context.WithoutCancel(ctx))
		if err != nil {
			errs = append(errs, fmt.Errorf("starting plugin service %q: %w", id, err))

			continue
		}

		b.sigHdlr.AddService(svc)
	}

	return errors.Join(errs...)
}

// mustStartDNS starts the DNS service and registers it in the signal handler.
// The DNS service is considered critical, so it panics instead of returning an
// error.
//
// [builder.initDNS] must be called before this method.
func (b *builder) mustStartDNS(ctx context.Context) {
	// The DNS service is considered critical, so its Start method panics
	// instead of returning an error.
	_ = b.dnsSvc.Start(context.WithoutCancel(ctx))

	b.sigHdlr.AddService(b.dnsSvc)

	b.logger.DebugContext(ctx, "started dns")
}

// mustInitDebugSvc initializes, starts, and registers the debug service.  The
// debug HTTP service is considered critical, so it panics instead of returning
// an error.
//
// The following methods must be called before this one:
//   - [builder.initBillStat]
//   - [builder.initDNS]
//   - [builder.initFilterStorage]
//   - [builder.initGeoIP]
//   - [builder.initHashPrefixFilters]
//   - [builder.initProfileDB]
//   - [builder.initRateLimiter]
//   - [builder.initRuleStat]
//   - [builder.initWeb]
func (b *builder) mustInitDebugSvc(ctx context.Context) {
	debugSvcConf := b.env.debugConf(b.dnsDB, b.baseLogger)
	debugSvcConf.Manager = b.cacheManager
	debugSvcConf.Refreshers = b.debugRefrs
	debugSvc := debugsvc.New(debugSvcConf)

	// The debug HTTP service is considered critical, so its Start method panics
	// instead of returning an error.
	_ = debugSvc.Start(context.WithoutCancel(ctx))

	b.sigHdlr.AddService(debugSvc)

	b.logger.DebugContext(
		ctx,
		"initialized debug",
		"refr_ids", slices.Collect(maps.Keys(b.debugRefrs)),
	)
}

// handleSignals blocks and processes signals from the OS.  status is
// [osutil.ExitCodeSuccess] on success and [osutil.ExitCodeFailure] on error.
//
// handleSignals must not be called concurrently with any other methods.
func (b *builder) handleSignals(ctx context.Context) (code osutil.ExitCode) {
	// TODO(s.chzhen):  Remove it.
	b.logger.DebugContext(ctx, "cache manager initialized", "ids", b.cacheManager.IDs())

	return b.sigHdlr.Handle(ctx)
}
