package filterstorage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/domain"
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

	s.resetDomainFilters(newDomainFilters)

	return nil
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
		Clock:            s.clock,
		URL:              cat.url,
		DomainMetrics:    s.domainMetrics,
		Metrics:          s.metrics,
		PublicSuffixList: publicsuffix.List,
		CategoryID:       catID,
		ResultListID:     filter.IDCategory,
		CachePath:        path.Join(s.cacheDir, filter.SubDirNameCategory, catIDStr),
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
