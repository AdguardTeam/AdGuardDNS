package filter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/bluele/gcache"
	"github.com/prometheus/client_golang/prometheus"
)

// Filter storage

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
	// mu protects ruleLists.
	mu *sync.RWMutex

	// URL is the URL of the filtering rule index document.  See filterIndexResp
	// and related types.
	url *url.URL

	// http is the HTTP client used to update the rule list filters from the
	// index.
	http *agdhttp.Client

	// ruleLists are the filter list ID to a rule list filter map.
	ruleLists map[agd.FilterListID]*ruleListFilter

	// services is the service blocking filter.
	services *serviceBlocker

	// safeBrowsing is the general safe browsing filter.
	safeBrowsing *hashPrefixFilter

	// adultBlocking is the adult content blocking safe browsing filter.
	adultBlocking *hashPrefixFilter

	// genSafeSearch is the general safe search filter.
	genSafeSearch *safeSearch

	// ytSafeSearch is the YouTube safe search filter.
	ytSafeSearch *safeSearch

	// now returns the current time.
	now func() (t time.Time)

	// errColl used to collect non-critical and rare errors, for example caching
	// errors.
	errColl agd.ErrorCollector

	// customFilters is the storage of custom filters for profiles.
	customFilters *customFilters

	// cacheDir is the path to the directory where the cached filter files are
	// put.  The directory must exist.
	cacheDir string

	// refreshIvl is the refresh interval for this storage.  It defines how
	// often the filter rule lists are updated from the index.
	refreshIvl time.Duration

	// RuleListCacheSize defines the size of the LRU cache of rule-list
	// filteirng results.
	ruleListCacheSize int

	// useRuleListCache, if true, enables rule list cache.
	useRuleListCache bool
}

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
	SafeBrowsing *HashPrefixConfig

	// AdultBlocking is the configuration for the adult content blocking safe
	// browsing filter.  It must not be nil.
	AdultBlocking *HashPrefixConfig

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
	// filteirng results.
	RuleListCacheSize int

	// RefreshIvl is the refresh interval for this storage.  It defines how
	// often the filter rule lists are updated from the index.
	RefreshIvl time.Duration

	// UseRuleListCache, if true, enables rule list cache.
	UseRuleListCache bool
}

// NewDefaultStorage returns a new filter storage.  c must not be nil.
func NewDefaultStorage(c *DefaultStorageConfig) (s *DefaultStorage, err error) {
	// TODO(ameshkov): Consider making configurable.
	resolver := agdnet.NewCachingResolver(c.Resolver, 1*timeutil.Day)

	safeBrowsing := newHashPrefixFilter(
		c.SafeBrowsing,
		resolver,
		c.ErrColl,
		agd.FilterListIDSafeBrowsing,
	)

	adultBlocking := newHashPrefixFilter(
		c.AdultBlocking,
		resolver,
		c.ErrColl,
		agd.FilterListIDAdultBlocking,
	)

	genSafeSearch := newSafeSearch(&safeSearchConfig{
		resolver: resolver,
		errColl:  c.ErrColl,
		list: &agd.FilterList{
			URL:        c.GeneralSafeSearchRulesURL,
			ID:         agd.FilterListIDGeneralSafeSearch,
			RefreshIvl: c.RefreshIvl,
		},
		cacheDir:  c.CacheDir,
		ttl:       c.SafeSearchCacheTTL,
		cacheSize: c.SafeSearchCacheSize,
	})

	ytSafeSearch := newSafeSearch(&safeSearchConfig{
		resolver: resolver,
		errColl:  c.ErrColl,
		list: &agd.FilterList{
			URL:        c.YoutubeSafeSearchRulesURL,
			ID:         agd.FilterListIDYoutubeSafeSearch,
			RefreshIvl: c.RefreshIvl,
		},
		cacheDir:  c.CacheDir,
		ttl:       c.SafeSearchCacheTTL,
		cacheSize: c.SafeSearchCacheSize,
	})

	s = &DefaultStorage{
		mu:  &sync.RWMutex{},
		url: c.FilterIndexURL,
		http: agdhttp.NewClient(&agdhttp.ClientConfig{
			Timeout: defaultTimeout,
		}),
		services:      newServiceBlocker(c.BlockedServiceIndexURL, c.ErrColl),
		safeBrowsing:  safeBrowsing,
		adultBlocking: adultBlocking,
		genSafeSearch: genSafeSearch,
		ytSafeSearch:  ytSafeSearch,
		now:           c.Now,
		errColl:       c.ErrColl,
		customFilters: &customFilters{
			cache:   gcache.New(c.CustomFilterCacheSize).LRU().Build(),
			errColl: c.ErrColl,
		},
		cacheDir:          c.CacheDir,
		refreshIvl:        c.RefreshIvl,
		ruleListCacheSize: c.RuleListCacheSize,
		useRuleListCache:  c.UseRuleListCache,
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

	flt := &compFilter{}

	g := ri.FilteringGroup
	if g.RuleListsEnabled {
		flt.ruleLists = append(flt.ruleLists, s.filters(g.RuleListIDs)...)
	}

	flt.safeBrowsing, flt.adultBlocking = s.safeBrowsingForGroup(g)
	flt.genSafeSearch, flt.ytSafeSearch = s.safeSearchForGroup(g)

	return flt
}

// filterForProfile returns a composite filter for profile.
func (s *DefaultStorage) filterForProfile(ctx context.Context, ri *agd.RequestInfo) (f Interface) {
	flt := &compFilter{}

	p := ri.Profile
	if !p.FilteringEnabled {
		// According to the current requirements, this means that the profile
		// should receive no filtering at all.
		return flt
	}

	d := ri.Device
	if d != nil && !d.FilteringEnabled {
		// According to the current requirements, this means that the device
		// should receive no filtering at all.
		return flt
	}

	// Assume that if we have a profile then we also have a device.

	flt.ruleLists = s.filters(p.RuleListIDs)
	flt.ruleLists = s.customFilters.appendRuleLists(ctx, flt.ruleLists, p)

	pp := p.Parental
	parentalEnabled := pp != nil && pp.Enabled && s.pcBySchedule(pp.Schedule)

	flt.ruleLists = append(flt.ruleLists, s.serviceFilters(p, parentalEnabled)...)

	flt.safeBrowsing, flt.adultBlocking = s.safeBrowsingForProfile(p, parentalEnabled)
	flt.genSafeSearch, flt.ytSafeSearch = s.safeSearchForProfile(p, parentalEnabled)

	return flt
}

// serviceFilters returns the blocked service rule lists for the profile.
//
// TODO(a.garipov): Consider not using ruleListFilter for service filters.  Due
// to performance reasons, it would be better to simply go through all enabled
// rules sequentially instead.  Alternatively, rework the urlfilter.DNSEngine
// and make it use the sequential scan if the number of rules is less than some
// constant value.
//
// See AGDNS-342.
func (s *DefaultStorage) serviceFilters(
	p *agd.Profile,
	parentalEnabled bool,
) (rls []*ruleListFilter) {
	if !parentalEnabled || len(p.Parental.BlockedServices) == 0 {
		return nil
	}

	return s.services.ruleLists(p.Parental.BlockedServices)
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
) (safeBrowsing, adultBlocking *hashPrefixFilter) {
	if p.SafeBrowsingEnabled {
		safeBrowsing = s.safeBrowsing
	}

	if parentalEnabled && p.Parental.BlockAdult {
		adultBlocking = s.adultBlocking
	}

	return safeBrowsing, adultBlocking
}

// safeSearchForProfile returns safe search filters based on the information in
// the profile.  p and p.Parental must not be nil.
func (s *DefaultStorage) safeSearchForProfile(
	p *agd.Profile,
	parentalEnabled bool,
) (gen, yt *safeSearch) {
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
) (safeBrowsing, adultBlocking *hashPrefixFilter) {
	if g.SafeBrowsingEnabled {
		safeBrowsing = s.safeBrowsing
	}

	if g.ParentalEnabled && g.BlockAdult {
		adultBlocking = s.adultBlocking
	}

	return safeBrowsing, adultBlocking
}

// safeSearchForGroup returns safe search filters based on the information in
// the filtering group.  g must not be nil.
func (s *DefaultStorage) safeSearchForGroup(g *agd.FilteringGroup) (gen, yt *safeSearch) {
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
func (s *DefaultStorage) filters(ids []agd.FilterListID) (rls []*ruleListFilter) {
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
	log.Info("%s: requesting %s", strgLogPrefix, s.url)

	resp, err := s.loadIndex(ctx)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	log.Info("%s: got %d filters from index", strgLogPrefix, len(resp.Filters))

	fls := resp.toInternal(ctx, s.errColl, s.refreshIvl)

	log.Info("%s: got %d filter lists from index after validations", strgLogPrefix, len(fls))

	ruleLists := make(map[agd.FilterListID]*ruleListFilter, len(resp.Filters))
	for _, fl := range fls {
		if _, ok := ruleLists[fl.ID]; ok {
			agd.Collectf(ctx, s.errColl, "%s: duplicated id %q", strgLogPrefix, fl.ID)

			continue
		}

		// TODO(a.garipov): Cache these.
		promLabels := prometheus.Labels{"filter": string(fl.ID)}

		rl := newRuleListFilter(fl, s.cacheDir, s.ruleListCacheSize, s.useRuleListCache)
		err = rl.refresh(ctx, acceptStale)
		if err == nil {
			ruleLists[fl.ID] = rl

			metrics.FilterUpdatedStatus.With(promLabels).Set(1)
			metrics.FilterUpdatedTime.With(promLabels).SetToCurrentTime()
			metrics.FilterRulesTotal.With(promLabels).Set(float64(rl.engine.RulesCount))

			continue
		}

		agd.Collectf(ctx, s.errColl, "%s: refreshing %q: %w", strgLogPrefix, fl.ID, err)
		metrics.FilterUpdatedStatus.With(promLabels).Set(0)

		// If we can't get the new filter, and there is an old version of the
		// same rule list, use it.
		rls := s.filters([]agd.FilterListID{fl.ID})
		if len(rls) > 0 {
			ruleLists[fl.ID] = rls[0]
		}
	}

	log.Info("%s: got %d filter lists from index after compilation", strgLogPrefix, len(ruleLists))

	err = s.services.refresh(ctx, s.ruleListCacheSize, s.useRuleListCache)
	if err != nil {
		return fmt.Errorf("refreshing service blocker: %w", err)
	}

	err = s.genSafeSearch.refresh(ctx, acceptStale)
	if err != nil {
		return fmt.Errorf("refreshing safe search: %w", err)
	}

	err = s.ytSafeSearch.refresh(ctx, acceptStale)
	if err != nil {
		return fmt.Errorf("refreshing safe search: %w", err)
	}

	s.setRuleLists(ruleLists)

	return nil
}

// loadIndex fetches, decodes, and returns the filter list index data of the
// storage.
func (s *DefaultStorage) loadIndex(ctx context.Context) (resp *filterIndexResp, err error) {
	defer func() { err = errors.Annotate(err, "loading filter index from %q: %w", s.url) }()

	httpResp, err := s.http.Get(ctx, s.url)
	if err != nil {
		return nil, fmt.Errorf("requesting: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, httpResp.Body.Close()) }()

	err = agdhttp.CheckStatus(httpResp, http.StatusOK)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	resp = &filterIndexResp{}
	err = json.NewDecoder(httpResp.Body).Decode(resp)
	if err != nil {
		return nil, fmt.Errorf("decoding: %w", err)
	}

	log.Debug("%s: loaded index with %d filters", strgLogPrefix, len(resp.Filters))

	return resp, nil
}

// setRuleLists replaces the storage's rule lists.
func (s *DefaultStorage) setRuleLists(ruleLists map[agd.FilterListID]*ruleListFilter) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, rl := range s.ruleLists {
		err := rl.Close()
		if err != nil {
			log.Error("%s: closing rule list %q: %s", strgLogPrefix, id, err)
		}
	}

	s.ruleLists = ruleLists
}

// filterIndexResp is the struct for the JSON response from a filter index API.
type filterIndexResp struct {
	Filters []*filterIndexRespFilter `json:"filters"`
}

// toInternal converts the filters from the index to []*agd.FilterList.
func (r *filterIndexResp) toInternal(
	ctx context.Context,
	errColl agd.ErrorCollector,
	refreshIvl time.Duration,
) (fls []*agd.FilterList) {
	fls = make([]*agd.FilterList, 0, len(r.Filters))
	for _, rf := range r.Filters {
		id, err := agd.NewFilterListID(rf.ID)
		if err != nil {
			agd.Collectf(ctx, errColl, "%s: validating id %q: %w", strgLogPrefix, rf.ID, err)

			continue
		}

		var u *url.URL
		u, err = agdhttp.ParseHTTPURL(rf.DownloadURL)
		if err != nil {
			agd.Collectf(
				ctx,
				errColl,
				"%s: validating url %q: %w",
				strgLogPrefix,
				rf.DownloadURL,
				err,
			)

			continue
		}

		fls = append(fls, &agd.FilterList{
			URL:        u,
			ID:         id,
			RefreshIvl: refreshIvl,
		})
	}

	return fls
}

// filterIndexRespFilter is the struct for a filter from the JSON response from
// a filter index API.
type filterIndexRespFilter struct {
	DownloadURL string `json:"downloadUrl"`
	ID          string `json:"filterId"`
}
