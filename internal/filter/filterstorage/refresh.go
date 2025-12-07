package filterstorage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path"
	"path/filepath"
	"slices"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/domain"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/service"
	"golang.org/x/net/publicsuffix"
)

// type check
var _ service.Refresher = (*Default)(nil)

// Refresh implements the [service.Refresher] interface for *Default.
func (s *Default) Refresh(ctx context.Context) (err error) {
	s.logger.InfoContext(ctx, "refresh started")
	defer s.logger.InfoContext(ctx, "refresh finished")

	err = s.refresh(ctx, false)
	if err != nil {
		errcoll.Collect(ctx, s.errColl, s.logger, "refresh", err)
	}

	return err
}

// refresh refreshes the rule-list, blocked-service, and safe-search filters.
// If acceptStale is true, the cache files are used regardless of their
// staleness.
func (s *Default) refresh(ctx context.Context, acceptStale bool) (err error) {
	newRuleLists, err := s.loadRuleLists(ctx, acceptStale)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	newDomainFilters, err := s.loadCategoryFilters(ctx, acceptStale)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	err = s.refreshServices(ctx, acceptStale)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	err = s.refreshSafeSearch(ctx, acceptStale)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	s.resetRuleLists(newRuleLists)
	s.resetDomainFilters(newDomainFilters)

	return nil
}

// loadRuleLists loads the rule-lists from the storage.  If acceptStale is true,
// the cache files are used regardless of their staleness.
func (s *Default) loadRuleLists(ctx context.Context, acceptStale bool) (rls ruleLists, err error) {
	if s.ruleListIdxRefr == nil {
		s.logger.DebugContext(ctx, "loading index skipped")

		return nil, nil
	}

	resp, err := s.loadIndex(ctx, acceptStale)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	s.logger.InfoContext(ctx, "loaded index", "num_filters", len(resp.Filters))

	fls := resp.toInternal(ctx, s.logger, s.errColl)
	s.logger.InfoContext(ctx, "validated lists", "num_lists", len(fls))

	newRuleLists, err := s.refreshRuleLists(ctx, fls, acceptStale)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	s.logger.InfoContext(ctx, "compiled lists", "num_lists", len(newRuleLists))

	return newRuleLists, nil
}

// loadCategoryFilters loads the category filter domain-lists from the storage.
// If acceptStale is true, the cache files are used regardless of their
// staleness.
func (s *Default) loadCategoryFilters(
	ctx context.Context,
	acceptStale bool,
) (dfs domainFilters, err error) {
	if s.categoryDomainsIdxRefr == nil {
		s.logger.DebugContext(ctx, "loading category index skipped")

		return nil, nil
	}

	resp, err := s.loadCategoryIndex(ctx, acceptStale)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	s.logger.InfoContext(ctx, "loaded category index")

	fls := resp.toInternal(ctx, s.logger, s.errColl)
	s.logger.InfoContext(ctx, "validated categories", "num_categories", len(fls))

	dfs, err = s.refreshDomainFilters(ctx, fls)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	s.logger.InfoContext(ctx, "compiled categories", "num_categories", len(dfs))

	return dfs, nil
}

// loadIndex fetches, decodes, and returns the filter list index data of the
// storage.  resp.Filters are sorted.
func (s *Default) loadIndex(ctx context.Context, acceptStale bool) (resp *indexResp, err error) {
	b, err := s.ruleListIdxRefr.Refresh(ctx, acceptStale)
	if err != nil {
		return nil, fmt.Errorf("loading index: %w", err)
	}

	resp = &indexResp{}
	err = json.Unmarshal(b, resp)
	if err != nil {
		return nil, fmt.Errorf("decoding: %w", err)
	}

	slices.SortStableFunc(resp.Filters, (*indexRespFilter).compare)

	return resp, nil
}

// loadCategoryIndex fetches, decodes, and returns the category filter list
// index data of the storage.
func (s *Default) loadCategoryIndex(
	ctx context.Context,
	acceptStale bool,
) (resp *categoryResp, err error) {
	b, err := s.categoryDomainsIdxRefr.Refresh(ctx, acceptStale)
	if err != nil {
		return nil, fmt.Errorf("loading index: %w", err)
	}

	resp = &categoryResp{}
	err = json.Unmarshal(b, resp)
	if err != nil {
		return nil, fmt.Errorf("decoding: %w", err)
	}

	return resp, nil
}

// refrResult is a result of refreshing a single rule list.
type refrResult struct {
	// refr is a refreshable filter created from the provided *indexData.  It
	// must not be nil if err is nil.
	refr *rulelist.Refreshable

	// err is a non-nil error if refreshing the rule list failed.
	err error

	// id is the ID of the rule list.
	id filter.ID
}

// refreshRuleLists concurrently handles the given filtersData.  Returns a map
// of new initialized and refreshed rule lists.
func (s *Default) refreshRuleLists(
	ctx context.Context,
	filtersData []*indexData,
	acceptStale bool,
) (rls ruleLists, err error) {
	lenFls := len(filtersData)

	resCh := make(chan refrResult, lenFls)
	for _, fl := range filtersData {
		go s.refreshRuleList(ctx, fl, acceptStale, resCh)
	}

	rls = make(ruleLists, lenFls)
	for range lenFls {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res := <-resCh:
			rls[res.id] = s.resultRuleList(ctx, res)
		}
	}

	return rls, nil
}

// resultRuleList returns a non-nil [rulelist.Refreshable] if res.err is nil.
// Otherwise, it returns the previous rule list for the given fltID and logs
// the error.
func (s *Default) resultRuleList(ctx context.Context, res refrResult) (rl *rulelist.Refreshable) {
	fltID := res.id
	if res.err != nil {
		err := fmt.Errorf("initializing rulelist %q: %w", fltID, res.err)
		errcoll.Collect(ctx, s.errColl, s.logger, "rule-list error", err)
		s.metrics.SetFilterStatus(ctx, string(fltID), s.clock.Now(), 0, err)

		return s.prevRuleList(fltID)
	}

	return res.refr
}

// prevRuleList returns the previous version of the filter, if there is one.
func (s *Default) prevRuleList(id filter.ID) (rl *rulelist.Refreshable) {
	s.ruleListsMu.RLock()
	defer s.ruleListsMu.RUnlock()

	var ok bool
	if rl, ok = s.ruleLists[id]; ok {
		return rl
	}

	return nil
}

// refreshRuleList creates a [rulelist.Refreshable] from the data loaded with
// fl.  It also adds the cache to the cache manager.  It is intended to be
// used as a goroutine.  fl must not be nil.
func (s *Default) refreshRuleList(
	ctx context.Context,
	fl *indexData,
	acceptStale bool,
	resCh chan<- refrResult,
) {
	defer func() {
		err := errors.FromRecovered(recover())
		if err == nil {
			return
		}

		s.logger.ErrorContext(ctx, "recovered panic", slogutil.KeyError, err)
		slogutil.PrintStack(ctx, s.logger, slog.LevelError)

		resCh <- refrResult{id: fl.id, err: err}
	}()

	fltID := fl.id
	res := refrResult{
		id: fltID,
	}

	fltIDStr := string(fltID)
	cacheID := path.Join(cachePrefixRuleList, fltIDStr)
	cache := rulelist.NewManagedResultCache(
		s.cacheManager,
		cacheID,
		s.ruleListResCacheCount,
		s.ruleListCacheEnabled,
	)

	rl, err := rulelist.NewRefreshable(&refreshable.Config{
		Logger:    s.baseLogger.With(slogutil.KeyPrefix, cacheID),
		URL:       fl.url,
		ID:        fltID,
		CachePath: filepath.Join(s.cacheDir, fltIDStr),
		Staleness: s.ruleListStaleness,
		Timeout:   s.ruleListRefreshTimeout,
		MaxSize:   s.ruleListMaxSize,
	}, cache)
	if err != nil {
		res.err = fmt.Errorf("creating rulelist: %w", err)
		resCh <- res

		return
	}

	err = rl.Refresh(ctx, acceptStale)
	if err != nil {
		res.err = fmt.Errorf("refreshing rulelist: %w", err)
		resCh <- res

		return
	}

	s.metrics.SetFilterStatus(ctx, fltIDStr, s.clock.Now(), rl.RulesCount(), nil)

	res.refr = rl
	resCh <- res
}

// refrDomainFilterResult is a result of refreshing a single domain filter.
type refrDomainFilterResult struct {
	// flt is a domain filter.  It must not be nil if err is nil.
	flt *domain.Filter

	// err is a non-nil error if refreshing failed.
	err error

	// catID is the category ID of the domain filter.
	catID filter.CategoryID
}

// refreshDomainFilters handles the given listsData.  Returns a map of new
// initialized and refreshed domain filters.
func (s *Default) refreshDomainFilters(
	ctx context.Context,
	data []*categoryData,
) (dls domainFilters, err error) {
	lenFls := len(data)

	resCh := make(chan refrDomainFilterResult, lenFls)
	for _, cat := range data {
		go s.refreshDomainFilter(ctx, cat, resCh)
	}

	dls = make(domainFilters, lenFls)
	for range lenFls {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res := <-resCh:
			dls[res.catID] = s.resultDomainFilter(ctx, res)
		}
	}

	return dls, nil
}

// refreshDomainFilter creates, refreshes and returns a domain filter for the
// given category data.  cat must not be nil.
func (s *Default) refreshDomainFilter(
	ctx context.Context,
	cat *categoryData,
	resCh chan<- refrDomainFilterResult,
) {
	defer func() {
		err := errors.FromRecovered(recover())
		if err == nil {
			return
		}

		s.logger.ErrorContext(ctx, "recovered panic", slogutil.KeyError, err)
		slogutil.PrintStack(ctx, s.logger, slog.LevelError)

		resCh <- refrDomainFilterResult{catID: cat.id, err: err}
	}()

	res := refrDomainFilterResult{
		catID: cat.id,
	}

	df, err := s.initDomainFilter(cat)
	if err != nil {
		res.err = fmt.Errorf("creating domain filter: %w", err)
		resCh <- res

		return
	}

	err = df.Refresh(ctx)
	if err != nil {
		res.err = fmt.Errorf("refreshing domain filter: %w", err)
		resCh <- res

		return
	}

	res.flt = df
	resCh <- res
}

// initDomainFilter creates a domain filter for the given category data.  cat
// must not be nil.
func (s *Default) initDomainFilter(cat *categoryData) (df *domain.Filter, err error) {
	catID := cat.id
	catIDStr := string(catID)
	cacheID := path.Join(domain.IDPrefix, catIDStr)

	return domain.NewFilter(&domain.FilterConfig{
		Logger:           s.baseLogger.With(slogutil.KeyPrefix, cacheID),
		CacheManager:     s.cacheManager,
		URL:              cat.url,
		ErrColl:          s.errColl,
		DomainMetrics:    s.domainMetrics,
		Metrics:          s.metrics,
		PublicSuffixList: publicsuffix.List,
		CategoryID:       catID,
		ResultListID:     filter.IDCategory,
		CachePath:        filepath.Join(s.cacheDir, catIDStr),
		Staleness:        s.categoryDomainsStaleness,
		RefreshTimeout:   s.categoryDomainsRefreshTimeout,
		CacheCount:       s.categoryDomainsResCacheCount,
		MaxSize:          s.categoryDomainsMaxSize,
		SubDomainNum:     s.domainFilterSubDomainNum,
	})
}

// resultDomainFilter returns a non-nil [domain.Filter] if res.err is nil.
// Otherwise, it returns the previous domain filter for the category and logs
// the error.
func (s *Default) resultDomainFilter(
	ctx context.Context,
	res refrDomainFilterResult,
) (rl *domain.Filter) {
	catID := res.catID
	if res.err != nil {
		err := fmt.Errorf("initializing domain filter %q: %w", catID, res.err)
		errcoll.Collect(ctx, s.errColl, s.logger, "domain filter error", err)

		return s.prevDomainFilter(catID)
	}

	return res.flt
}

// prevDomainFilter returns the previous version of the filter, if there is one.
func (s *Default) prevDomainFilter(id filter.CategoryID) (df *domain.Filter) {
	s.domainFiltersMu.RLock()
	defer s.domainFiltersMu.RUnlock()

	var ok bool
	if df, ok = s.domainFilters[id]; ok {
		return df
	}

	return nil
}

// refreshServices refreshes the blocked-service filter, if necessary.
func (s *Default) refreshServices(ctx context.Context, acceptStale bool) (err error) {
	if s.services == nil {
		return nil
	}

	err = s.services.Refresh(
		ctx,
		s.cacheManager,
		s.serviceResCacheCount,
		s.serviceResCacheEnabled,
		acceptStale,
	)
	if err != nil {
		return fmt.Errorf("refreshing blocked services: %w", err)
	}

	return nil
}

// refreshSafeSearch refreshes the safe-search filters, if necessary.
func (s *Default) refreshSafeSearch(ctx context.Context, acceptStale bool) (err error) {
	if s.safeSearchGeneral != nil {
		err = s.safeSearchGeneral.Refresh(ctx, acceptStale)
	}
	if err != nil {
		return fmt.Errorf("refreshing general safe search: %w", err)
	}

	if s.safeSearchYouTube != nil {
		err = s.safeSearchYouTube.Refresh(ctx, acceptStale)
	}
	if err != nil {
		return fmt.Errorf("refreshing youtube safe search: %w", err)
	}

	return nil
}

// resetRuleLists replaces the storage's rule lists.
func (s *Default) resetRuleLists(rls ruleLists) {
	s.ruleListsMu.Lock()
	defer s.ruleListsMu.Unlock()

	s.ruleLists = rls
}

// resetDomainFilters replaces the storage's domain filters.
func (s *Default) resetDomainFilters(dfs domainFilters) {
	s.domainFiltersMu.Lock()
	defer s.domainFiltersMu.Unlock()

	s.domainFilters = dfs
}

// RefreshInitial loads the content of the storage, using cached files if any,
// regardless of their staleness.
func (s *Default) RefreshInitial(ctx context.Context) (err error) {
	s.logger.InfoContext(ctx, "initial refresh started")
	defer s.logger.InfoContext(ctx, "initial refresh finished")

	err = s.refresh(ctx, true)
	if err != nil {
		return fmt.Errorf("refreshing filter storage initially: %w", err)
	}

	return nil
}
