package filterstorage

import (
	"context"
	"fmt"
	"log/slog"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/composite"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/domain"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/safesearch"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/serviceblock"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/ruleliststorage"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/typosquatting"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/c2h5oh/datasize"
)

// Default is the default filter storage that assembles filters based on rule
// lists, safe browsing, and safe search ones.  It should be initially refreshed
// with [Default.RefreshInitial].
type Default struct {
	baseLogger *slog.Logger
	logger     *slog.Logger

	services *serviceblock.Filter

	adult           *hashprefix.Filter
	dangerous       *hashprefix.Filter
	newlyRegistered *hashprefix.Filter

	safeSearchGeneral *safesearch.Filter
	safeSearchYouTube *safesearch.Filter

	typosquatting *typosquatting.Filter

	// domainFiltersMu protects domainFilters.
	domainFiltersMu *sync.RWMutex
	domainFilters   domainFilters

	categoryDomainsIdxRefr *refreshable.Refreshable

	cacheManager    agdcache.Manager
	clock           timeutil.Clock
	domainMetrics   domain.Metrics
	errColl         errcoll.Interface
	metrics         filter.Metrics
	ruleListStorage ruleliststorage.Storage

	cacheDir string

	categoryDomainsStaleness      time.Duration
	categoryDomainsRefreshTimeout time.Duration

	categoryDomainsMaxSize datasize.ByteSize

	categoryDomainsResCacheCount uint64
	serviceResCacheCount         uint64

	domainFilterSubDomainNum uint

	serviceResCacheEnabled bool
}

// domainFilters is convenient alias for a category ID to filter mapping.
type domainFilters = map[filter.CategoryID]*domain.Filter

// New returns a new default filter storage ready for initial refresh with
// [Default.RefreshInitial].  c must not be nil.
func New(c *Config) (s *Default, err error) {
	// NOTE:  Since this is a large and complex structure, enumerate all fields
	// explicitly here to make it easier to recheck changes later.
	s = &Default{
		baseLogger: c.BaseLogger,
		logger:     c.Logger,

		// Initialized in [Default.initBlockedServices].
		services: nil,

		adult:           c.HashPrefix.Adult,
		dangerous:       c.HashPrefix.Dangerous,
		newlyRegistered: c.HashPrefix.NewlyRegistered,

		// Initialized in [Default.init].
		typosquatting: nil,

		// Initialized in [Default.initSafeSearch].
		safeSearchGeneral: nil,
		safeSearchYouTube: nil,

		domainFiltersMu: &sync.RWMutex{},

		// Initialized in [Default.RefreshInitial].
		domainFilters: nil,

		// Initialized in [Default.initCategoryDomainIdxRefr].
		categoryDomainsIdxRefr: nil,

		cacheManager:    c.CacheManager,
		clock:           c.Clock,
		domainMetrics:   c.DomainMetrics,
		errColl:         c.ErrColl,
		metrics:         c.Metrics,
		ruleListStorage: c.RuleListStorage,

		cacheDir: c.CacheDir,

		categoryDomainsStaleness:      c.CategoryDomainsIndex.Staleness,
		categoryDomainsRefreshTimeout: c.CategoryDomainsIndex.RefreshTimeout,

		categoryDomainsMaxSize: c.CategoryDomainsIndex.MaxSize,

		categoryDomainsResCacheCount: c.CategoryDomainsIndex.ResultCacheCount,
		serviceResCacheCount:         c.BlockedServices.ResultCacheCount,

		domainFilterSubDomainNum: c.DomainFilterSubDomainNum,

		serviceResCacheEnabled: c.BlockedServices.ResultCacheEnabled,
	}

	err = s.init(c)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return s, nil
}

// init finishes the initialization of a storage.  c must not be nil.
func (s *Default) init(c *Config) (err error) {
	var errs []error
	err = s.initBlockedServices(c.BlockedServices)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		errs = append(errs, err)
	}

	err = s.initSafeSearch(c.SafeSearchGeneral, c.SafeSearchYouTube)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		errs = append(errs, err)
	}

	err = s.initCategoryDomainIdxRefr(c.CategoryDomainsIndex)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		errs = append(errs, err)
	}

	if c.Typosquatting.Enabled {
		s.typosquatting = c.Typosquatting.Filter
	}

	return errors.Join(errs...)
}

// initBlockedServices initializes the blocked-service filter in s.  c must not
// be nil.
func (s *Default) initBlockedServices(c *BlockedServicesConfig) (err error) {
	if !c.Enabled {
		return nil
	}

	refrConf := &refreshable.Config{
		Logger: s.baseLogger.With(
			slogutil.KeyPrefix, path.Join("filters", string(FilterIDBlockedServiceIndex)),
		),
		URL:       c.IndexURL,
		ID:        filter.ID(FilterIDBlockedServiceIndex),
		CachePath: filepath.Join(s.cacheDir, filter.SubDirNameIndex, indexFileNameBlockedServices),
		Staleness: c.IndexStaleness,
		Timeout:   c.IndexRefreshTimeout,
		MaxSize:   c.IndexMaxSize,
	}

	s.services, err = serviceblock.New(&serviceblock.Config{
		Refreshable: refrConf,
		ErrColl:     s.errColl,
		Metrics:     s.metrics,
	})
	if err != nil {
		return fmt.Errorf("blocked-service filter: %w", err)
	}

	return nil
}

// initSafeSearch initializes the safe-search filters in s.  gen and yt must not
// be nil.
func (s *Default) initSafeSearch(gen, yt *SafeSearchConfig) (err error) {
	s.safeSearchGeneral, err = newSafeSearch(s.baseLogger, gen, s.cacheManager, s.cacheDir)
	if err != nil {
		return fmt.Errorf("general safe search: %w", err)
	}

	s.safeSearchYouTube, err = newSafeSearch(s.baseLogger, yt, s.cacheManager, s.cacheDir)
	if err != nil {
		return fmt.Errorf("youtube safe search: %w", err)
	}

	return nil
}

// newSafeSearch returns a new safe-search filter for the storage.  All
// arguments must not be empty.
func newSafeSearch(
	baseLogger *slog.Logger,
	c *SafeSearchConfig,
	cacheMgr agdcache.Manager,
	cacheDir string,
) (f *safesearch.Filter, err error) {
	if !c.Enabled {
		return nil, nil
	}

	fltIDStr := string(c.ID)
	cacheID := path.Join(cachePrefixSafeSearch, fltIDStr)
	cache := rulelist.NewManagedResultCache(cacheMgr, cacheID, c.ResultCacheCount, true)

	return safesearch.New(
		&safesearch.Config{
			Refreshable: &refreshable.Config{
				Logger:    baseLogger.With(slogutil.KeyPrefix, cacheID),
				URL:       c.URL,
				ID:        c.ID,
				CachePath: filepath.Join(cacheDir, filter.SubDirNameSafeSearch, fltIDStr),
				Staleness: c.Staleness,
				Timeout:   c.RefreshTimeout,
				MaxSize:   c.MaxSize,
			},
			CacheTTL: c.ResultCacheTTL,
		},
		cache,
	)
}

// initCategoryDomainIdxRefr initializes the category filter domain-list
// refresher in s.  c must not be nil.
func (s *Default) initCategoryDomainIdxRefr(c *IndexConfig) (err error) {
	if !c.Enabled {
		return nil
	}

	s.categoryDomainsIdxRefr, err = refreshable.New(&refreshable.Config{
		Logger: s.baseLogger.With(
			slogutil.KeyPrefix,
			path.Join("category_filters", string(FilterIDCategoryDomainsIndex)),
		),
		URL:       c.IndexURL,
		ID:        FilterIDCategoryDomainsIndex,
		CachePath: filepath.Join(s.cacheDir, filter.SubDirNameIndex, indexFileNameCategoryDomains),
		Staleness: c.IndexStaleness,
		Timeout:   c.IndexRefreshTimeout,
		MaxSize:   c.IndexMaxSize,
	})
	if err != nil {
		return fmt.Errorf("category domain-list index: %w", err)
	}

	return nil
}

// type check
var _ filter.Storage = (*Default)(nil)

// ForConfig implements the [filter.Storage] interface for *Default.
func (s *Default) ForConfig(ctx context.Context, c filter.Config) (f filter.Interface) {
	switch c := c.(type) {
	case nil:
		return filter.Empty{}
	case *filter.ConfigClient:
		return s.forClient(ctx, c)
	case *filter.ConfigGroup:
		return s.forGroup(ctx, c)
	default:
		panic(fmt.Errorf("filter config: %w: %T(%[2]v)", errors.ErrBadEnumValue, c))
	}
}

// forClient returns a new filter based on a client configuration.  c must not
// be nil.
func (s *Default) forClient(ctx context.Context, c *filter.ConfigClient) (f filter.Interface) {
	compConf := &composite.Config{
		// TODO(a.garipov):  Find ways of reusing these.  Perhaps add Close to
		// [filter.Interface]?
		URLFilterRequest: &urlfilter.DNSRequest{},
		URLFilterResult:  &urlfilter.DNSResult{},
	}

	s.setParental(ctx, compConf, c.Parental)
	s.setCustomRuleLists(ctx, compConf, c.CustomRuleList)
	s.setRuleLists(ctx, compConf, c.RuleList)
	s.setSafeBrowsing(compConf, c.SafeBrowsing)

	if c.CustomFilter.Enabled {
		compConf.Custom = c.CustomFilter.Filter
	}

	return composite.New(compConf)
}

// setParental checks if the parental-control filters are enabled and, if they
// are, sets them in compConf from c.  c must not be nil.
func (s *Default) setParental(
	ctx context.Context,
	compConf *composite.Config,
	c *filter.ConfigParental,
) {
	if !c.Enabled {
		return
	}

	pause := c.PauseSchedule
	if pause != nil && pause.Contains(s.clock.Now()) {
		return
	}

	s.setEnabledParental(ctx, compConf, c)
}

// setEnabledParental sets the parental-control filters in compConf from c.  c
// must not be nil.
func (s *Default) setEnabledParental(
	ctx context.Context,
	compConf *composite.Config,
	c *filter.ConfigParental,
) {
	// NOTE:  Here and below always check the pointer for nil to avoid non-nil
	// interface values containing nil pointers.
	if c.AdultBlockingEnabled && s.adult != nil {
		compConf.AdultBlocking = s.adult
	}

	if c.SafeSearchGeneralEnabled && s.safeSearchGeneral != nil {
		compConf.GeneralSafeSearch = s.safeSearchGeneral
	}

	if c.SafeSearchYouTubeEnabled && s.safeSearchYouTube != nil {
		compConf.YouTubeSafeSearch = s.safeSearchYouTube
	}

	if len(c.BlockedServices) > 0 && s.services != nil {
		compConf.ServiceLists = s.services.RuleLists(ctx, c.BlockedServices)
	}

	s.setDomainFilters(compConf, c.Categories)
}

// setDomainFilters sets the category domain filters in compConf from c.  c must
// not be nil.
func (s *Default) setDomainFilters(compConf *composite.Config, c *filter.ConfigCategories) {
	if !c.Enabled || len(c.IDs) == 0 {
		return
	}

	s.domainFiltersMu.RLock()
	defer s.domainFiltersMu.RUnlock()

	for _, id := range c.IDs {
		fl := s.domainFilters[id]
		if fl != nil {
			compConf.CategoryFilters = append(compConf.CategoryFilters, fl)
		}
	}
}

// setCustomRuleLists sets the custom rule-list filters in compConf from c.  c
// and compConf must not be nil.
func (s *Default) setCustomRuleLists(
	ctx context.Context,
	compConf *composite.Config,
	c *filter.ConfigCustomRuleList,
) {
	if !c.Enabled || len(c.IDs) == 0 {
		return
	}

	compConf.CustomRuleLists = s.ruleListStorage.AppendForListIDs(
		ctx,
		compConf.CustomRuleLists,
		c.IDs,
	)
}

// setRuleLists sets the rule-list filters in compConf from c.  c and compConf
// must not be nil.
func (s *Default) setRuleLists(
	ctx context.Context,
	compConf *composite.Config,
	c *filter.ConfigRuleList,
) {
	if !c.Enabled || len(c.IDs) == 0 {
		return
	}

	compConf.RuleLists = s.ruleListStorage.AppendForListIDs(ctx, compConf.RuleLists, c.IDs)
}

// setSafeBrowsing sets the safe-browsing filters in compConf from c.  c must
// not be nil.
func (s *Default) setSafeBrowsing(compConf *composite.Config, c *filter.ConfigSafeBrowsing) {
	if !c.Enabled {
		return
	}

	if c.DangerousDomainsEnabled && s.dangerous != nil {
		compConf.SafeBrowsing = s.dangerous
	}

	if c.NewlyRegisteredDomainsEnabled && s.newlyRegistered != nil {
		compConf.NewRegisteredDomains = s.newlyRegistered
	}

	if c.Typosquatting != nil && c.Typosquatting.Enabled && s.typosquatting != nil {
		compConf.Typosquatting = s.typosquatting
	}
}

// forGroup returns a new filter based on a group configuration.  c must not be
// nil.
func (s *Default) forGroup(ctx context.Context, c *filter.ConfigGroup) (f filter.Interface) {
	compConf := &composite.Config{
		// TODO(a.garipov):  Find ways of reusing these.  Perhaps add Close to
		// [filter.Interface]?
		URLFilterRequest: &urlfilter.DNSRequest{},
		URLFilterResult:  &urlfilter.DNSResult{},
	}

	s.setParental(ctx, compConf, c.Parental)
	s.setRuleLists(ctx, compConf, c.RuleList)
	s.setSafeBrowsing(compConf, c.SafeBrowsing)

	return composite.New(compConf)
}
