package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
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
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/AdGuardDNS/internal/rulestat"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/c2h5oh/datasize"
	"github.com/prometheus/client_golang/prometheus"
)

// Constants that define debug identifiers for the debug HTTP service.
const (
	debugIDAllowlist     = "allowlist"
	debugIDBillStat      = "billstat"
	debugIDGeoIP         = "geoip"
	debugIDProfileDB     = "profiledb"
	debugIDRuleStat      = "rulestat"
	debugIDTicketRotator = "ticket_rotator"
	debugIDWebSvc        = "websvc"
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
	cloner         *dnsmsg.Cloner
	conf           *configuration
	env            *environment
	errColl        errcoll.Interface
	geoIPError     chan error
	logger         *slog.Logger
	mtrcNamespace  string
	plugins        *plugin.Registry
	promRegisterer prometheus.Registerer
	sigHdlr        *service.SignalHandler

	// The fields below are initialized later by calling the builder's methods.
	// Keep them sorted.

	access              *access.Global
	adultBlocking       *hashprefix.Filter
	adultBlockingHashes *hashprefix.Storage
	backendGRPCMtrc     *metrics.BackendPB
	billStat            billstat.Recorder
	bindSet             netutil.SubnetSet
	btdManager          *bindtodevice.Manager
	connLimit           *connlimiter.Limiter
	controlConf         *netext.ControlConfig
	dnsCheck            dnscheck.Interface
	dnsDB               dnsdb.Interface
	dnsSvc              *dnssvc.Service
	filterStorage       *filter.DefaultStorage
	filteringGroups     map[agd.FilteringGroupID]*agd.FilteringGroup
	fwdHandler          *forward.Handler
	geoIP               *geoip.File
	hashMatcher         *hashprefix.Matcher
	messages            *dnsmsg.Constructor
	newRegDomains       *hashprefix.Filter
	newRegDomainsHashes *hashprefix.Storage
	profileDB           profiledb.Interface
	rateLimit           *ratelimit.Backoff
	debugRefrs          debugsvc.Refreshers
	ruleStat            rulestat.Interface
	safeBrowsing        *hashprefix.Filter
	safeBrowsingHashes  *hashprefix.Storage
	sdeConf             *dnsmsg.StructuredDNSErrorsConfig
	tlsMtrc             tlsconfig.Metrics
	webSvc              *websvc.Service

	// The fields below are initialized later, just like with the fields above,
	// but are placed in this order for alignment optimization.

	serverGroups    []*agd.ServerGroup
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
}

// shutdownTimeout is the default shutdown timeout for all services.
const shutdownTimeout = 5 * time.Second

// newBuilder returns a new properly initialized builder.  c must not be nil.
func newBuilder(c *builderConfig) (b *builder) {
	cloner := dnsmsg.NewCloner(metrics.ClonerStat{})

	return &builder{
		baseLogger:     c.baseLogger,
		cacheManager:   agdcache.NewDefaultManager(),
		cloner:         cloner,
		conf:           c.conf,
		env:            c.envs,
		errColl:        c.errColl,
		geoIPError:     make(chan error, 1),
		logger:         c.baseLogger.With(slogutil.KeyPrefix, "builder"),
		mtrcNamespace:  metrics.Namespace(),
		plugins:        c.plugins,
		promRegisterer: prometheus.DefaultRegisterer,
		debugRefrs:     debugsvc.Refreshers{},
		sigHdlr: service.NewSignalHandler(&service.SignalHandlerConfig{
			Logger:          c.baseLogger.With(slogutil.KeyPrefix, service.SignalHandlerPrefix),
			ShutdownTimeout: shutdownTimeout,
		}),
	}
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

	c := b.conf.GeoIP
	b.geoIP = geoip.NewFile(&geoip.FileConfig{
		Logger:         b.baseLogger.With(slogutil.KeyPrefix, "geoip"),
		CacheManager:   b.cacheManager,
		ASNPath:        asn,
		CountryPath:    ctry,
		HostCacheSize:  c.HostCacheSize,
		IPCacheSize:    c.IPCacheSize,
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

// initHashPrefixFilters initializes the hashprefix storages and filters.
func (b *builder) initHashPrefixFilters(ctx context.Context) (err error) {
	// TODO(a.garipov):  Make a separate max_size config for hashprefix filters.
	maxSize := b.conf.Filters.MaxSize
	cacheDir := b.env.FilterCachePath

	matchers := map[string]*hashprefix.Storage{}

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
// [hashprefix.IDPrefix]/[agd.FilterListIDAdultBlocking] to the debug
// refreshers.
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

	b.adultBlockingHashes, err = hashprefix.NewStorage("")
	if err != nil {
		// Don't expect errors here because we pass an empty string.
		panic(err)
	}

	c := b.conf.AdultBlocking
	id := agd.FilterListIDAdultBlocking
	prefix := path.Join(hashprefix.IDPrefix, string(id))
	b.adultBlocking, err = hashprefix.NewFilter(&hashprefix.FilterConfig{
		Logger:          b.baseLogger.With(slogutil.KeyPrefix, prefix),
		Cloner:          b.cloner,
		CacheManager:    b.cacheManager,
		Hashes:          b.adultBlockingHashes,
		URL:             &b.env.AdultBlockingURL.URL,
		ErrColl:         b.errColl,
		ID:              id,
		CachePath:       filepath.Join(cacheDir, string(id)),
		ReplacementHost: c.BlockHost,
		Staleness:       c.RefreshIvl.Duration,
		RefreshTimeout:  c.RefreshTimeout.Duration,
		CacheTTL:        c.CacheTTL.Duration,
		// TODO(a.garipov):  Make all sizes [datasize.ByteSize] and rename cache
		// entity counts to fooCount.
		CacheSize: c.CacheSize,
		MaxSize:   maxSize,
	})
	if err != nil {
		return fmt.Errorf("creating filter: %w", err)
	}

	err = b.adultBlocking.RefreshInitial(ctx)
	if err != nil {
		return fmt.Errorf("initial refresh: %w", err)
	}

	refr := agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		// Note that we also set the same timeout for the http.Client in
		// [hashprefix.NewFilter].
		Context:           newCtxWithTimeoutCons(c.RefreshTimeout.Duration),
		Refresher:         b.adultBlocking,
		Logger:            b.baseLogger.With(slogutil.KeyPrefix, string(id)+"_refresh"),
		Interval:          c.RefreshIvl.Duration,
		RefreshOnShutdown: false,
		RandomizeStart:    false,
	})
	err = refr.Start(ctx)
	if err != nil {
		return fmt.Errorf("starting refresher: %w", err)
	}

	b.sigHdlr.Add(refr)

	matchers[filter.AdultBlockingTXTSuffix] = b.adultBlockingHashes

	b.debugRefrs[prefix] = b.adultBlocking

	return nil
}

// initNewRegDomains initializes the newly-registered domain filter and hash
// storage.  It also adds the refresher with ID
// [hashprefix.IDPrefix]/[agd.FilterListIDNewRegDomains] to the debug
// refreshers.
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

	b.newRegDomainsHashes, err = hashprefix.NewStorage("")
	if err != nil {
		// Don't expect errors here because we pass an empty string.
		panic(err)
	}

	// Reuse the general safe-browsing filter configuration with a new URL and
	// ID.
	c := b.conf.SafeBrowsing
	id := agd.FilterListIDNewRegDomains
	prefix := path.Join(hashprefix.IDPrefix, string(id))
	b.newRegDomains, err = hashprefix.NewFilter(&hashprefix.FilterConfig{
		Logger:          b.baseLogger.With(slogutil.KeyPrefix, prefix),
		Cloner:          b.cloner,
		CacheManager:    b.cacheManager,
		Hashes:          b.newRegDomainsHashes,
		URL:             &b.env.NewRegDomainsURL.URL,
		ErrColl:         b.errColl,
		ID:              id,
		CachePath:       filepath.Join(cacheDir, string(id)),
		ReplacementHost: c.BlockHost,
		Staleness:       c.RefreshIvl.Duration,
		RefreshTimeout:  c.RefreshTimeout.Duration,
		CacheTTL:        c.CacheTTL.Duration,
		CacheSize:       c.CacheSize,
		MaxSize:         maxSize,
	})
	if err != nil {
		return fmt.Errorf("creating filter: %w", err)
	}

	err = b.newRegDomains.RefreshInitial(ctx)
	if err != nil {
		return fmt.Errorf("initial refresh: %w", err)
	}

	refr := agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		// Note that we also set the same timeout for the http.Client in
		// [hashprefix.NewFilter].
		Context:           newCtxWithTimeoutCons(c.RefreshTimeout.Duration),
		Refresher:         b.newRegDomains,
		Logger:            b.baseLogger.With(slogutil.KeyPrefix, string(id)+"_refresh"),
		Interval:          c.RefreshIvl.Duration,
		RefreshOnShutdown: false,
		RandomizeStart:    false,
	})
	err = refr.Start(ctx)
	if err != nil {
		return fmt.Errorf("starting refresher: %w", err)
	}

	b.sigHdlr.Add(refr)

	b.debugRefrs[prefix] = b.newRegDomains

	return nil
}

// initSafeBrowsing initializes the safe-browsing filter and hash storage.  It
// also adds the refresher with ID
// [hashprefix.IDPrefix]/[agd.FilterListIDSafeBrowsing] to the debug refreshers.
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

	b.safeBrowsingHashes, err = hashprefix.NewStorage("")
	if err != nil {
		// Don't expect errors here because we pass an empty string.
		panic(err)
	}

	c := b.conf.SafeBrowsing
	id := agd.FilterListIDSafeBrowsing
	prefix := path.Join(hashprefix.IDPrefix, string(id))
	b.safeBrowsing, err = hashprefix.NewFilter(&hashprefix.FilterConfig{
		Logger:          b.baseLogger.With(slogutil.KeyPrefix, prefix),
		Cloner:          b.cloner,
		CacheManager:    b.cacheManager,
		Hashes:          b.safeBrowsingHashes,
		URL:             &b.env.SafeBrowsingURL.URL,
		ErrColl:         b.errColl,
		ID:              id,
		CachePath:       filepath.Join(cacheDir, string(id)),
		ReplacementHost: c.BlockHost,
		Staleness:       c.RefreshIvl.Duration,
		RefreshTimeout:  c.RefreshTimeout.Duration,
		CacheTTL:        c.CacheTTL.Duration,
		CacheSize:       c.CacheSize,
		MaxSize:         maxSize,
	})
	if err != nil {
		return fmt.Errorf("creating filter: %w", err)
	}

	err = b.safeBrowsing.RefreshInitial(ctx)
	if err != nil {
		return fmt.Errorf("initial refresh: %w", err)
	}

	refr := agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		// Note that we also set the same timeout for the http.Client in
		// [hashprefix.NewFilter].
		Context:           newCtxWithTimeoutCons(c.RefreshTimeout.Duration),
		Refresher:         b.safeBrowsing,
		Logger:            b.baseLogger.With(slogutil.KeyPrefix, string(id)+"_refresh"),
		Interval:          c.RefreshIvl.Duration,
		RefreshOnShutdown: false,
		RandomizeStart:    false,
	})
	err = refr.Start(ctx)
	if err != nil {
		return fmt.Errorf("starting refresher: %w", err)
	}

	b.sigHdlr.Add(refr)

	matchers[filter.GeneralTXTSuffix] = b.safeBrowsingHashes

	b.debugRefrs[prefix] = b.safeBrowsing

	return nil
}

// initFilterStorage initializes and refreshes the filter storage.  It also adds
// the refresher with ID [filter.StoragePrefix] to the debug refreshers.
//
// [builder.initHashPrefixFilters] must be called before this method.
func (b *builder) initFilterStorage(ctx context.Context) (err error) {
	c := b.conf.Filters
	b.filterStorage = filter.NewDefaultStorage(c.toInternal(
		b.baseLogger,
		b.errColl,
		b.cacheManager,
		b.env,
		b.safeBrowsing,
		b.adultBlocking,
		b.newRegDomains,
	))

	err = b.filterStorage.RefreshInitial(ctx)
	if err != nil {
		return fmt.Errorf("creating default filter storage: %w", err)
	}

	refr := agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		Context:           newCtxWithTimeoutCons(c.RefreshIvl.Duration),
		Refresher:         b.filterStorage,
		Logger:            b.baseLogger.With(slogutil.KeyPrefix, "filters/storage_refresh"),
		Interval:          c.RefreshIvl.Duration,
		RefreshOnShutdown: false,
		RandomizeStart:    false,
	})
	err = refr.Start(ctx)
	if err != nil {
		return fmt.Errorf("starting default filter storage update: %w", err)
	}

	b.sigHdlr.Add(refr)

	b.debugRefrs[filter.StoragePrefix] = b.filterStorage

	b.logger.DebugContext(ctx, "initialized filter storage")

	return nil
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

	var btdCtrlConf *bindtodevice.ControlConfig
	btdCtrlConf, b.controlConf = c.Network.toInternal()
	b.btdManager, err = c.InterfaceListeners.toInternal(b.baseLogger, b.errColl, btdCtrlConf)
	if err != nil {
		return fmt.Errorf("converting interface listeners: %w", err)
	}

	b.logger.DebugContext(ctx, "initialized bindtodevice manager")

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
		FilteredResponseTTL: fltConf.ResponseTTL.Duration,
		EDEEnabled:          fltConf.EDEEnabled,
	})
	if err != nil {
		return fmt.Errorf("creating dns message constructor: %w", err)
	}

	b.logger.DebugContext(ctx, "initialized dns message constructor")

	return nil
}

// initServerGroups initializes the server groups.
//
// The following methods must be called before this one:
//   - [builder.initBindToDevice]
//   - [builder.initFilteringGroups]
//   - [builder.initMsgConstructor]
func (b *builder) initServerGroups(ctx context.Context) (err error) {
	mtrc, err := metrics.NewTLSConfig(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("registering tls metrics: %w", err)
	}

	b.tlsMtrc = mtrc

	c := b.conf
	b.serverGroups, err = c.ServerGroups.toInternal(
		ctx,
		mtrc,
		b.messages,
		b.btdManager,
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

// setServerGroupProperties sets b.profilesEnabled and b.bindSet depending on
// the server-group data.
func (b *builder) setServerGroupProperties(ctx context.Context) {
	var serverPrefixes []netip.Prefix
	allSingleIP := true
	for _, grp := range b.serverGroups {
		b.profilesEnabled = b.profilesEnabled || grp.ProfilesEnabled

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
	err = b.btdManager.Start(ctx)
	if err != nil {
		return fmt.Errorf("starting bindtodevice manager: %w", err)
	}

	b.sigHdlr.Add(b.btdManager)

	b.logger.DebugContext(ctx, "started bindtodevice manager")

	return nil
}

// initTLS initializes the optional TLS key logging and session-ticket rotation.
// It also adds the refresher with ID [debugIDTicketRotator] to the debug
// refreshers.
//
// [builder.initServerGroups] must be called before this method.
func (b *builder) initTLS(ctx context.Context) (err error) {
	if f := b.env.SSLKeyLogFile; f != "" {
		b.logger.WarnContext(ctx, "IMPORTANT: TLS KEY LOGGING IS ENABLED", "ssl_key_log_file", f)

		err = enableTLSKeyLogging(b.serverGroups, f)
		if err != nil {
			return fmt.Errorf("enabling tls key logging: %w", err)
		}
	}

	tickRot := newTicketRotator(b.baseLogger, b.errColl, b.tlsMtrc, b.serverGroups)
	err = tickRot.Refresh(ctx)
	if err != nil {
		return fmt.Errorf("initial session ticket refresh: %w", err)
	}

	refr := agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		Context:   ctxWithDefaultTimeout,
		Refresher: tickRot,
		Logger:    b.baseLogger.With(slogutil.KeyPrefix, "tickrot_refresh"),
		// TODO(a.garipov):  Make configurable.
		Interval:          1 * time.Minute,
		RefreshOnShutdown: false,
		RandomizeStart:    false,
	})
	err = refr.Start(ctx)
	if err != nil {
		return fmt.Errorf("starting ticket rotator refresh: %w", err)
	}

	b.sigHdlr.Add(refr)

	b.debugRefrs[debugIDTicketRotator] = tickRot

	b.logger.DebugContext(ctx, "initialized tls")

	return nil
}

// initGRPCMetrics initializes the gRPC metrics if necessary.
func (b *builder) initGRPCMetrics(ctx context.Context) (err error) {
	switch {
	case
		b.profilesEnabled,
		b.conf.Check.RemoteKV.Type == kvModeBackend,
		b.conf.RateLimit.Allowlist.Type == rlAllowlistTypeBackend:
		// Go on.
	default:
		// Don't initialize the metrics if no protobuf backend is used.
		return nil
	}

	b.backendGRPCMtrc, err = metrics.NewBackendPB(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("registering backendbp metrics: %w", err)
	}

	b.logger.DebugContext(ctx, "initialized grpc metrics")

	return nil
}

// initBillStat initializes the billing-statistics recorder if necessary.  It
// also adds the refresher with ID [debugIDBillStat] to the debug refreshers.
func (b *builder) initBillStat(ctx context.Context) (err error) {
	if !b.profilesEnabled {
		b.billStat = billstat.EmptyRecorder{}

		return nil
	}

	upl, err := newBillStatUploader(b.env, b.errColl, b.backendGRPCMtrc)
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
	refrIvl := c.BillStatIvl.Duration
	timeout := c.Timeout.Duration

	b.billStat = billStat
	refr := agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		Context:           newCtxWithTimeoutCons(timeout),
		Refresher:         billStat,
		Logger:            b.baseLogger.With(slogutil.KeyPrefix, "billstat_refresh"),
		Interval:          refrIvl,
		RefreshOnShutdown: true,
		RandomizeStart:    false,
	})
	err = refr.Start(ctx)
	if err != nil {
		return fmt.Errorf("starting billstat recorder refresher: %w", err)
	}

	b.sigHdlr.Add(refr)

	b.debugRefrs[debugIDBillStat] = billStat

	b.logger.DebugContext(ctx, "initialized billstat")

	return nil
}

// initProfileDB initializes the profile database if necessary.
//
// [builder.initGRPCMetrics] and [builder.initServerGroups] must be called
// before this method.  It also adds the refresher with ID [debugIDProfileDB] to
// the debug refreshers.
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

	respSzEst := b.conf.RateLimit.ResponseSizeEstimate
	strg, err := backendpb.NewProfileStorage(&backendpb.ProfileStorageConfig{
		BindSet:              b.bindSet,
		ErrColl:              b.errColl,
		Logger:               b.baseLogger.With(slogutil.KeyPrefix, "backendpb"),
		Metrics:              b.backendGRPCMtrc,
		Endpoint:             apiURL,
		APIKey:               b.env.ProfilesAPIKey,
		ResponseSizeEstimate: respSzEst,
		MaxProfilesSize:      b.env.ProfilesMaxRespSize,
	})
	if err != nil {
		return fmt.Errorf("creating profile storage: %w", err)
	}

	profDBMtrc, err := metrics.NewProfileDB(b.mtrcNamespace, b.promRegisterer)
	if err != nil {
		return fmt.Errorf("registering profile database metrics: %w", err)
	}

	c := b.conf.Backend
	timeout := c.Timeout.Duration
	profDB, err := profiledb.New(&profiledb.Config{
		Logger:               b.baseLogger.With(slogutil.KeyPrefix, "profiledb"),
		Storage:              strg,
		ErrColl:              b.errColl,
		Metrics:              profDBMtrc,
		CacheFilePath:        b.env.ProfilesCachePath,
		FullSyncIvl:          c.FullRefreshIvl.Duration,
		FullSyncRetryIvl:     c.FullRefreshRetryIvl.Duration,
		ResponseSizeEstimate: respSzEst,
	})
	if err != nil {
		return fmt.Errorf("creating default profile database: %w", err)
	}

	err = initProfDB(ctx, b.logger, profDB, timeout)
	if err != nil {
		return fmt.Errorf("preparing default profile database: %w", err)
	}

	// TODO(a.garipov):  Add a separate refresher ID for full refreshes.
	b.profileDB = profDB
	refr := agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		Context:           newCtxWithTimeoutCons(timeout),
		Logger:            b.baseLogger.With(slogutil.KeyPrefix, "profiledb_refresh"),
		Refresher:         profDB,
		Interval:          c.RefreshIvl.Duration,
		RefreshOnShutdown: false,
		RandomizeStart:    true,
	})
	err = refr.Start(ctx)
	if err != nil {
		return fmt.Errorf("starting default profile database refresher: %w", err)
	}

	b.sigHdlr.Add(refr)

	b.debugRefrs[debugIDProfileDB] = profDB

	b.logger.DebugContext(ctx, "initialized profiledb")

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
	u := b.env.RuleStatURL
	if u == nil {
		b.logger.WarnContext(ctx, "not collecting rule statistics")

		b.ruleStat = rulestat.Empty{}

		return nil
	}

	ruleStat := rulestat.NewHTTP(&rulestat.HTTPConfig{
		Logger:  b.baseLogger.With(slogutil.KeyPrefix, "rulestat"),
		ErrColl: b.errColl,
		URL:     &u.URL,
	})

	b.ruleStat = ruleStat
	refr := agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		Context:   ctxWithDefaultTimeout,
		Refresher: ruleStat,
		Logger:    b.baseLogger.With(slogutil.KeyPrefix, "rulestat_refresh"),
		// TODO(a.garipov):  Make configurable.
		Interval:          10 * time.Minute,
		RefreshOnShutdown: true,
		RandomizeStart:    false,
	})
	err = refr.Start(ctx)
	if err != nil {
		return fmt.Errorf("starting rulestat refresher: %w", err)
	}

	b.sigHdlr.Add(refr)

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

	typ := b.conf.RateLimit.Allowlist.Type
	mtrc, err := metrics.NewAllowlist(b.mtrcNamespace, b.promRegisterer, typ)
	if err != nil {
		return fmt.Errorf("ratelimit metrics: %w", err)
	}

	var updater agdservice.Refresher
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

	refr := agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		Context:           ctxWithDefaultTimeout,
		Refresher:         updater,
		Logger:            b.baseLogger.With(slogutil.KeyPrefix, "ratelimit_allowlist_refresh"),
		Interval:          c.Allowlist.RefreshIvl.Duration,
		RefreshOnShutdown: false,
		RandomizeStart:    false,
	})
	err = refr.Start(ctx)
	if err != nil {
		return fmt.Errorf("starting allowlist refresher: %w", err)
	}

	b.sigHdlr.Add(refr)

	b.connLimit = c.ConnectionLimit.toInternal(b.baseLogger)
	b.rateLimit = ratelimit.NewBackoff(c.toInternal(allowlist))

	b.debugRefrs[debugIDAllowlist] = updater

	b.logger.DebugContext(ctx, "initialized ratelimit")

	return nil
}

// initWeb initializes the web service, starts it, and registers it in the
// signal handler.
//
// [builder.initServerGroups] must be called before this method.
func (b *builder) initWeb(ctx context.Context) (err error) {
	c := b.conf.Web
	webConf, err := c.toInternal(ctx, b.env, b.dnsCheck, b.errColl, b.tlsMtrc)
	if err != nil {
		return fmt.Errorf("converting web configuration: %w", err)
	}

	b.webSvc = websvc.New(webConf)

	err = b.webSvc.Refresh(ctx)
	if err != nil {
		return fmt.Errorf("web: initial refresh: %w", err)
	}

	refr := agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		Context:   ctxWithDefaultTimeout,
		Refresher: b.webSvc,
		Logger:    b.baseLogger.With(slogutil.KeyPrefix, "websvc_refresh"),
		// TODO(a.garipov): Consider making configurable.
		Interval:          5 * time.Minute,
		RefreshOnShutdown: false,
		RandomizeStart:    false,
	})
	err = refr.Start(ctx)
	if err != nil {
		return fmt.Errorf("starting websvc refresher: %w", err)
	}

	b.sigHdlr.Add(refr)

	// The web service is considered critical, so its Start method panics
	// instead of returning an error.
	_ = b.webSvc.Start(ctx)

	b.sigHdlr.Add(b.webSvc)

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
	refr := agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		Context: ctxWithDefaultTimeout,
		// Do not add errColl to geoip's config, as that would create an import
		// cycle.
		//
		// TODO(a.garipov):  Resolve that.
		Refresher: agdservice.NewRefresherWithErrColl(
			b.geoIP,
			refrLogger,
			b.errColl,
			prefix,
		),
		Logger:            refrLogger,
		Interval:          b.conf.GeoIP.RefreshIvl.Duration,
		RefreshOnShutdown: false,
		RandomizeStart:    false,
	})
	err = refr.Start(ctx)
	if err != nil {
		return fmt.Errorf("starting geoip refresher: %w", err)
	}

	b.sigHdlr.Add(refr)

	b.debugRefrs[debugIDGeoIP] = b.geoIP

	return nil
}

// initDNS initializes the DNS service.
//
// The following methods must be called before this one:
//   - [builder.initAccess]
//   - [builder.initBillStat]
//   - [builder.initBindToDevice]
//   - [builder.initDNSCheck]
//   - [builder.initFilterStorage]
//   - [builder.initFilteringGroups]
//   - [builder.initMsgConstructor]
//   - [builder.initProfileDB]
//   - [builder.initRateLimiter]
//   - [builder.initRuleStat]
//   - [builder.initWeb]
//   - [builder.waitGeoIP]
func (b *builder) initDNS(ctx context.Context) (err error) {
	b.fwdHandler = forward.NewHandler(b.conf.Upstream.toInternal(b.baseLogger))
	b.dnsDB = b.conf.DNSDB.toInternal(b.errColl)

	dnsHdlrsConf := &dnssvc.HandlersConfig{
		BaseLogger:           b.baseLogger,
		Cache:                b.conf.Cache.toInternal(),
		Cloner:               b.cloner,
		HumanIDParser:        agd.NewHumanIDParser(),
		Messages:             b.messages,
		PluginRegistry:       b.plugins,
		StructuredErrors:     b.sdeConf,
		AccessManager:        b.access,
		BillStat:             b.billStat,
		CacheManager:         b.cacheManager,
		DNSCheck:             b.dnsCheck,
		DNSDB:                b.dnsDB,
		ErrColl:              b.errColl,
		FilterStorage:        b.filterStorage,
		GeoIP:                b.geoIP,
		Handler:              b.fwdHandler,
		HashMatcher:          b.hashMatcher,
		ProfileDB:            b.profileDB,
		PrometheusRegisterer: b.promRegisterer,
		QueryLog:             b.queryLog(),
		RateLimit:            b.rateLimit,
		RuleStat:             b.ruleStat,
		MetricsNamespace:     b.mtrcNamespace,
		FilteringGroups:      b.filteringGroups,
		ServerGroups:         b.serverGroups,
		EDEEnabled:           b.conf.Filters.EDEEnabled,
	}

	dnsHdlrs, err := dnssvc.NewHandlers(ctx, dnsHdlrsConf)
	if err != nil {
		return fmt.Errorf("dns handlers: %w", err)
	}

	dnsConf := &dnssvc.Config{
		Handlers:         dnsHdlrs,
		Cloner:           b.cloner,
		ControlConf:      b.controlConf,
		ConnLimiter:      b.connLimit,
		NonDNS:           b.webSvc,
		ErrColl:          b.errColl,
		MetricsNamespace: b.mtrcNamespace,
		ServerGroups:     b.serverGroups,
		HandleTimeout:    b.conf.DNS.HandleTimeout.Duration,
	}

	b.dnsSvc, err = dnssvc.New(dnsConf)
	if err != nil {
		return fmt.Errorf("dns service: %w", err)
	}

	b.logger.DebugContext(ctx, "initialized dns")

	return nil
}

// queryLog returns the appropriate query log implementation from the
// configuration and environment data.
func (b *builder) queryLog() (l querylog.Interface) {
	fileNeeded := b.conf.QueryLog.File.Enabled
	if !fileNeeded {
		return querylog.Empty{}
	}

	return querylog.NewFileSystem(&querylog.FileSystemConfig{
		Logger: b.baseLogger.With(slogutil.KeyPrefix, "querylog"),
		Path:   b.env.QueryLogPath,
		// #nosec G115 -- The Unix epoch time is highly unlikely to be negative.
		RandSeed: uint64(time.Now().UnixNano()),
	})
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
	err = upd.Start(ctx)
	if err != nil {
		return fmt.Errorf("initializing healthcheck: %w", err)
	}

	b.sigHdlr.Add(upd)

	b.logger.DebugContext(ctx, "initialized healthcheck")

	return nil
}

// mustStartDNS starts the DNS service and registers it in the signal handler.
// The DNS service is considered critical, so it panics instead of returning an
// error.
//
// [builder.initDNS] must be called before this method.
func (b *builder) mustStartDNS(ctx context.Context) {
	// The DNS service is considered critical, so its Start method panics
	// instead of returning an error.
	_ = b.dnsSvc.Start(ctx)

	b.sigHdlr.Add(b.dnsSvc)

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
	_ = debugSvc.Start(ctx)

	b.sigHdlr.Add(debugSvc)

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
