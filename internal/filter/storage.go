package filter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/composite"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/custom"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/safesearch"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/serviceblock"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/log"
	"github.com/bluele/gcache"
)

// Storage is a storage for filters.
type Storage interface {
	// FilterFromContext returns a filter combining rules and types of filtering
	// for all entities from the context.  ri must not be nil.
	FilterFromContext(ctx context.Context, ri *agd.RequestInfo) (f Interface)

	// HasListID returns true if id is within the rule lists that are currently
	// in the storage.
	HasListID(id agd.FilterListID) (ok bool)
}

// DefaultStorage is the default storage for filters, including the filters
// based on rule lists, custom filters of profiles, safe browsing, and safe
// search ones.
type DefaultStorage struct {
	// refr is the helper entity containing the refreshable part of the index
	// refresh and caching logic.
	refr *internal.Refreshable

	// mu protects ruleLists.
	mu *sync.RWMutex

	// ruleLists are the filter list ID to a rule list filter map.
	ruleLists filteringRuleLists

	// services is the service blocking filter.
	services *serviceblock.Filter

	// safeBrowsing is the general safe browsing filter.
	safeBrowsing *hashprefix.Filter

	// adultBlocking is the adult content blocking safe browsing filter.
	adultBlocking *hashprefix.Filter

	// newRegDomains is the newly registered domains filter.
	newRegDomains *hashprefix.Filter

	// genSafeSearch is the general safe search filter.
	genSafeSearch *safesearch.Filter

	// ytSafeSearch is the YouTube safe search filter.
	ytSafeSearch *safesearch.Filter

	// now returns the current time.
	now func() (t time.Time)

	// errColl used to collect non-critical and rare errors, for example caching
	// errors.
	errColl agd.ErrorCollector

	// customFilters is the storage of custom filters for profiles.
	customFilters *custom.Filters

	// cacheDir is the path to the directory where the cached filter files are
	// put.  The directory must exist.
	cacheDir string

	// refreshIvl is the refresh interval for this storage.  It defines how
	// often the filter rule lists are updated from the index.
	refreshIvl time.Duration

	// RuleListCacheSize defines the size of the LRU cache of rule-list
	// filtering results.
	ruleListCacheSize int

	// maxRuleListSize is the maximum size in bytes of the downloadable
	// rule-list content.
	maxRuleListSize int64

	// useRuleListCache, if true, enables rule list cache.
	useRuleListCache bool
}

// filteringRuleLists is convenient alias for an ID to filter mapping.
type filteringRuleLists = map[agd.FilterListID]*rulelist.Refreshable

// Filenames for filter indexes.
//
// TODO(ameshkov): Consider making configurable.
const (
	ruleListIndexFilename = "filters.json"
	serviceIndexFilename  = "services.json"
)

// DefaultStorageConfig contains configuration for a filter storage based on
// rule lists.
type DefaultStorageConfig struct {
	// FilterIndexURL is the URL of the filtering rule index document.
	FilterIndexURL *url.URL

	// BlockedServiceIndexURL is the URL of the blocked service index document.
	BlockedServiceIndexURL *url.URL

	// GeneralSafeSearchRulesURL is the URL to refresh general safe search rules
	// list.
	GeneralSafeSearchRulesURL *url.URL

	// YoutubeSafeSearchRulesURL is the URL to refresh YouTube safe search rules
	// list.
	YoutubeSafeSearchRulesURL *url.URL

	// SafeBrowsing is the configuration for the default safe browsing filter.
	// It must not be nil.
	SafeBrowsing *hashprefix.Filter

	// AdultBlocking is the configuration for the adult content blocking safe
	// browsing filter.  It must not be nil.
	AdultBlocking *hashprefix.Filter

	// NewRegDomains is the configuration for the newly registered domains safe
	// browsing filter.  It must not be nil.
	NewRegDomains *hashprefix.Filter

	// Now is a function that returns current time.
	Now func() (now time.Time)

	// ErrColl is used to collect non-critical and rare errors.
	ErrColl agd.ErrorCollector

	// Resolver is used to resolve hosts in safe search.
	Resolver agdnet.Resolver

	// CacheDir is the path to the directory where the cached filter files are
	// put.  The directory must exist.
	CacheDir string

	// CustomFilterCacheSize is the number of cached custom filters for
	// profiles.
	CustomFilterCacheSize int

	// SafeSearchCacheSize is the size of the LRU cache of results of the safe
	// search filters: the general one and the YouTube one.
	SafeSearchCacheSize int

	// SafeSearchCacheTTL is the time-to-live value used for the cache of
	// results of the safe search filters: the general one and the YouTube one.
	SafeSearchCacheTTL time.Duration

	// RuleListCacheSize defines the size of the LRU cache of rule-list
	// filtering results.
	RuleListCacheSize int

	// RefreshIvl is the refresh interval for this storage.  It defines how
	// often the filter rule lists are updated from the index.
	//
	// TODO(a.garipov): This value is used both for refreshes and for filter
	// staleness, which can cause issues.  Consider splitting the two.
	RefreshIvl time.Duration

	// UseRuleListCache, if true, enables rule list cache.
	UseRuleListCache bool

	// MaxRuleListSize is the maximum size in bytes of the downloadable
	// rule-list content.
	MaxRuleListSize int64
}

// NewDefaultStorage returns a new filter storage.  c must not be nil.
func NewDefaultStorage(c *DefaultStorageConfig) (s *DefaultStorage, err error) {
	genSafeSearch := safesearch.New(&safesearch.Config{
		Refreshable: &internal.RefreshableConfig{
			URL:       c.GeneralSafeSearchRulesURL,
			ID:        agd.FilterListIDGeneralSafeSearch,
			CachePath: filepath.Join(c.CacheDir, string(agd.FilterListIDGeneralSafeSearch)),
			Staleness: c.RefreshIvl,
			// TODO(ameshkov): Consider making configurable.
			Timeout: internal.DefaultFilterRefreshTimeout,
			MaxSize: c.MaxRuleListSize,
		},
		Resolver:  c.Resolver,
		ErrColl:   c.ErrColl,
		CacheTTL:  c.SafeSearchCacheTTL,
		CacheSize: c.SafeSearchCacheSize,
	})

	ytSafeSearch := safesearch.New(&safesearch.Config{
		Refreshable: &internal.RefreshableConfig{
			URL:       c.YoutubeSafeSearchRulesURL,
			ID:        agd.FilterListIDYoutubeSafeSearch,
			CachePath: filepath.Join(c.CacheDir, string(agd.FilterListIDYoutubeSafeSearch)),
			Staleness: c.RefreshIvl,
			// TODO(ameshkov): Consider making configurable.
			Timeout: internal.DefaultFilterRefreshTimeout,
			MaxSize: c.MaxRuleListSize,
		},
		Resolver:  c.Resolver,
		ErrColl:   c.ErrColl,
		CacheTTL:  c.SafeSearchCacheTTL,
		CacheSize: c.SafeSearchCacheSize,
	})

	ruleListIdxRefr := internal.NewRefreshable(&internal.RefreshableConfig{
		URL: c.FilterIndexURL,
		// TODO(a.garipov): Consider adding special IDs for indexes.
		ID:        "rule_list_index",
		CachePath: filepath.Join(c.CacheDir, ruleListIndexFilename),
		Staleness: c.RefreshIvl,
		// TODO(ameshkov): Consider making configurable.
		Timeout: internal.DefaultFilterRefreshTimeout,
		// TODO(a.garipov): Consider using a different limit here.
		MaxSize: c.MaxRuleListSize,
	})

	svcIdxRefr := internal.NewRefreshable(&internal.RefreshableConfig{
		URL: c.BlockedServiceIndexURL,
		// TODO(a.garipov): Consider adding special IDs for indexes.
		ID:        "blocked_service_index",
		CachePath: filepath.Join(c.CacheDir, serviceIndexFilename),
		Staleness: c.RefreshIvl,
		// TODO(ameshkov): Consider making configurable.
		Timeout: internal.DefaultFilterRefreshTimeout,
		// TODO(a.garipov): Consider using a different limit here.
		MaxSize: c.MaxRuleListSize,
	})

	s = &DefaultStorage{
		refr:          ruleListIdxRefr,
		mu:            &sync.RWMutex{},
		services:      serviceblock.New(svcIdxRefr, c.ErrColl),
		safeBrowsing:  c.SafeBrowsing,
		adultBlocking: c.AdultBlocking,
		newRegDomains: c.NewRegDomains,
		genSafeSearch: genSafeSearch,
		ytSafeSearch:  ytSafeSearch,
		now:           c.Now,
		errColl:       c.ErrColl,
		customFilters: custom.New(
			gcache.New(c.CustomFilterCacheSize).LRU().Build(),
			c.ErrColl,
		),
		cacheDir:          c.CacheDir,
		refreshIvl:        c.RefreshIvl,
		ruleListCacheSize: c.RuleListCacheSize,
		useRuleListCache:  c.UseRuleListCache,
		maxRuleListSize:   c.MaxRuleListSize,
	}

	err = s.refresh(context.Background(), true)
	if err != nil {
		return nil, fmt.Errorf("initial refresh: %w", err)
	}

	return s, nil
}

// type check
var _ Storage = (*DefaultStorage)(nil)

// FilterFromContext implements the Storage interface for *DefaultStorage.
func (s *DefaultStorage) FilterFromContext(ctx context.Context, ri *agd.RequestInfo) (f Interface) {
	if ri.Profile != nil {
		return s.filterForProfile(ctx, ri)
	}

	c := &composite.Config{}

	g := ri.FilteringGroup
	if g.RuleListsEnabled {
		c.RuleLists = s.filters(g.RuleListIDs)
	}

	c.SafeBrowsing, c.AdultBlocking, c.NewRegisteredDomains = s.safeBrowsingForGroup(g)
	c.GeneralSafeSearch, c.YouTubeSafeSearch = s.safeSearchForGroup(g)

	return composite.New(c)
}

// filterForProfile returns a composite filter for profile.
func (s *DefaultStorage) filterForProfile(ctx context.Context, ri *agd.RequestInfo) (f Interface) {
	p := ri.Profile
	if !p.FilteringEnabled {
		// According to the current requirements, this means that the profile
		// should receive no filtering at all.
		return composite.New(nil)
	}

	d := ri.Device
	if d != nil && !d.FilteringEnabled {
		// According to the current requirements, this means that the device
		// should receive no filtering at all.
		return composite.New(nil)
	}

	// Assume that if we have a profile then we also have a device.

	c := &composite.Config{}
	c.RuleLists = s.filters(p.RuleListIDs)
	c.Custom = s.customFilters.Get(ctx, p)

	pp := p.Parental
	parentalEnabled := pp != nil && pp.Enabled && s.pcBySchedule(pp.Schedule)

	c.ServiceLists = s.serviceFilters(ctx, p, parentalEnabled)

	c.SafeBrowsing, c.AdultBlocking, c.NewRegisteredDomains = s.safeBrowsingForProfile(p, parentalEnabled)
	c.GeneralSafeSearch, c.YouTubeSafeSearch = s.safeSearchForProfile(p, parentalEnabled)

	return composite.New(c)
}

// serviceFilters returns the blocked service rule lists for the profile.
func (s *DefaultStorage) serviceFilters(
	ctx context.Context,
	p *agd.Profile,
	parentalEnabled bool,
) (rls []*rulelist.Immutable) {
	if !parentalEnabled || len(p.Parental.BlockedServices) == 0 {
		return nil
	}

	return s.services.RuleLists(ctx, p.Parental.BlockedServices)
}

// pcBySchedule returns true if the profile's schedule allows parental control
// filtering at the moment.
func (s *DefaultStorage) pcBySchedule(sch *agd.ParentalProtectionSchedule) (ok bool) {
	if sch == nil {
		// No schedule, so always filter.
		return true
	}

	return !sch.Contains(s.now())
}

// safeBrowsingForProfile returns safe browsing filters based on the information
// in the profile.  p and p.Parental must not be nil.
func (s *DefaultStorage) safeBrowsingForProfile(
	p *agd.Profile,
	parentalEnabled bool,
) (safeBrowsing, adultBlocking, newRegDomains *hashprefix.Filter) {
	if p.SafeBrowsing != nil && p.SafeBrowsing.Enabled {
		if p.SafeBrowsing.BlockDangerousDomains {
			safeBrowsing = s.safeBrowsing
		}

		if p.SafeBrowsing.BlockNewlyRegisteredDomains {
			newRegDomains = s.newRegDomains
		}
	}

	if parentalEnabled && p.Parental.BlockAdult {
		adultBlocking = s.adultBlocking
	}

	return safeBrowsing, adultBlocking, newRegDomains
}

// safeSearchForProfile returns safe search filters based on the information in
// the profile.  p and p.Parental must not be nil.
func (s *DefaultStorage) safeSearchForProfile(
	p *agd.Profile,
	parentalEnabled bool,
) (gen, yt *safesearch.Filter) {
	if !parentalEnabled {
		return nil, nil
	}

	if p.Parental.GeneralSafeSearch {
		gen = s.genSafeSearch
	}

	if p.Parental.YoutubeSafeSearch {
		yt = s.ytSafeSearch
	}

	return gen, yt
}

// safeBrowsingForGroup returns safe browsing filters based on the information
// in the filtering group.  g must not be nil.
func (s *DefaultStorage) safeBrowsingForGroup(
	g *agd.FilteringGroup,
) (safeBrowsing, adultBlocking, newRegDomains *hashprefix.Filter) {
	if g.SafeBrowsingEnabled {
		if g.BlockDangerousDomains {
			safeBrowsing = s.safeBrowsing
		}

		if g.BlockNewlyRegisteredDomains {
			newRegDomains = s.newRegDomains
		}
	}

	if g.ParentalEnabled && g.BlockAdult {
		adultBlocking = s.adultBlocking
	}

	return safeBrowsing, adultBlocking, newRegDomains
}

// safeSearchForGroup returns safe search filters based on the information in
// the filtering group.  g must not be nil.
func (s *DefaultStorage) safeSearchForGroup(g *agd.FilteringGroup) (gen, yt *safesearch.Filter) {
	if !g.ParentalEnabled {
		return nil, nil
	}

	if g.GeneralSafeSearch {
		gen = s.genSafeSearch
	}

	if g.YoutubeSafeSearch {
		yt = s.ytSafeSearch
	}

	return gen, yt
}

// filters returns all rule list filters with the given filtering rule list IDs.
func (s *DefaultStorage) filters(ids []agd.FilterListID) (rls []*rulelist.Refreshable) {
	if len(ids) == 0 {
		return nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, id := range ids {
		rl := s.ruleLists[id]
		if rl != nil {
			rls = append(rls, rl)
		}
	}

	return rls
}

// HasListID implements the Storage interface for *DefaultStorage.
func (s *DefaultStorage) HasListID(id agd.FilterListID) (ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, ok = s.ruleLists[id]

	return ok
}

// type check
var _ agd.Refresher = (*DefaultStorage)(nil)

// strgLogPrefix is the logging prefix for reportable errors and logs that
// DefaultStorage.Refresh uses.
const strgLogPrefix = "filter storage: refresh"

// Refresh implements the agd.Refresher interface for *DefaultStorage.
func (s *DefaultStorage) Refresh(ctx context.Context) (err error) {
	return s.refresh(ctx, false)
}

// refresh is the inner method of Refresh that allows accepting stale files.  It
// refreshes the index from the index URL and updates all rule list filters, as
// well as the service filters.
func (s *DefaultStorage) refresh(ctx context.Context, acceptStale bool) (err error) {
	resp, err := s.loadIndex(ctx, acceptStale)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	log.Info("%s: got %d filters from index", strgLogPrefix, len(resp.Filters))

	fls := resp.toInternal(ctx, s.errColl)

	log.Info("%s: got %d filter lists from index after validations", strgLogPrefix, len(fls))

	ruleLists := make(filteringRuleLists, len(resp.Filters))
	for _, fl := range fls {
		s.addRuleList(ctx, ruleLists, fl, acceptStale)
	}

	log.Info("%s: got %d filter lists from index after compilation", strgLogPrefix, len(ruleLists))

	err = s.services.Refresh(ctx, s.ruleListCacheSize, s.useRuleListCache, acceptStale)
	if err != nil {
		const errFmt = "refreshing blocked services: %w"
		agd.Collectf(ctx, s.errColl, errFmt, err)

		return fmt.Errorf(errFmt, err)
	}

	err = s.genSafeSearch.Refresh(ctx, acceptStale)
	if err != nil {
		return fmt.Errorf("refreshing safe search: %w", err)
	}

	err = s.ytSafeSearch.Refresh(ctx, acceptStale)
	if err != nil {
		return fmt.Errorf("refreshing safe search: %w", err)
	}

	s.setRuleLists(ruleLists)

	return nil
}

// addRuleList adds the data from fl to ruleLists and handles all validations
// and errors.
func (s *DefaultStorage) addRuleList(
	ctx context.Context,
	ruleLists filteringRuleLists,
	fl *filterIndexFilterData,
	acceptStale bool,
) {
	if _, ok := ruleLists[fl.id]; ok {
		agd.Collectf(ctx, s.errColl, "%s: duplicated id %q", strgLogPrefix, fl.id)

		return
	}

	fltIDStr := string(fl.id)
	rl := rulelist.NewRefreshable(
		&internal.RefreshableConfig{
			URL:       fl.url,
			ID:        fl.id,
			CachePath: filepath.Join(s.cacheDir, fltIDStr),
			Staleness: s.refreshIvl,
			// TODO(ameshkov): Consider making configurable.
			Timeout: internal.DefaultFilterRefreshTimeout,
			MaxSize: s.maxRuleListSize,
		},
		s.ruleListCacheSize,
		s.useRuleListCache,
	)
	err := rl.Refresh(ctx, acceptStale)
	if err == nil {
		ruleLists[fl.id] = rl

		metrics.FilterUpdatedStatus.WithLabelValues(fltIDStr).Set(1)
		metrics.FilterUpdatedTime.WithLabelValues(fltIDStr).SetToCurrentTime()
		metrics.FilterRulesTotal.WithLabelValues(fltIDStr).Set(float64(rl.RulesCount()))

		return
	}

	agd.Collectf(ctx, s.errColl, "%s: refreshing %q: %w", strgLogPrefix, fl.id, err)
	metrics.FilterUpdatedStatus.WithLabelValues(fltIDStr).Set(0)

	// If we can't get the new filter, and there is an old version of the same
	// rule list, use it.
	rls := s.filters([]agd.FilterListID{fl.id})
	if len(rls) > 0 {
		ruleLists[fl.id] = rls[0]
	}
}

// loadIndex fetches, decodes, and returns the filter list index data of the
// storage.
func (s *DefaultStorage) loadIndex(
	ctx context.Context,
	acceptStale bool,
) (resp *filterIndexResp, err error) {
	text, err := s.refr.Refresh(ctx, acceptStale)
	if err != nil {
		return nil, fmt.Errorf("loading index: %w", err)
	}

	resp = &filterIndexResp{}
	err = json.NewDecoder(strings.NewReader(text)).Decode(resp)
	if err != nil {
		return nil, fmt.Errorf("decoding: %w", err)
	}

	return resp, nil
}

// setRuleLists replaces the storage's rule lists.
func (s *DefaultStorage) setRuleLists(ruleLists filteringRuleLists) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ruleLists = ruleLists
}
