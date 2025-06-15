package filterstorage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/service"
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
	resp, err := s.loadIndex(ctx, acceptStale)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	s.logger.InfoContext(ctx, "loaded index", "num_filters", len(resp.Filters))

	fls := resp.toInternal(ctx, s.logger, s.errColl)
	s.logger.InfoContext(ctx, "validated lists", "num_lists", len(fls))

	newRuleLists := s.refreshRuleLists(ctx, fls, acceptStale)
	s.logger.InfoContext(ctx, "compiled lists", "num_lists", len(newRuleLists))

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

	return nil
}

// loadIndex fetches, decodes, and returns the filter list index data of the
// storage.  resp.Filters are sorted.
func (s *Default) loadIndex(
	ctx context.Context,
	acceptStale bool,
) (resp *indexResp, err error) {
	text, err := s.ruleListIdxRefr.Refresh(ctx, acceptStale)
	if err != nil {
		return nil, fmt.Errorf("loading index: %w", err)
	}

	resp = &indexResp{}
	err = json.NewDecoder(strings.NewReader(text)).Decode(resp)
	if err != nil {
		return nil, fmt.Errorf("decoding: %w", err)
	}

	slices.SortStableFunc(resp.Filters, (*indexRespFilter).compare)

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
) (rls ruleLists) {
	lenFls := len(filtersData)

	resCh := make(chan refrResult, lenFls)
	for _, fl := range filtersData {
		go s.refreshRuleList(ctx, fl, acceptStale, resCh)
	}

	rls = make(ruleLists, lenFls)
	for range lenFls {
		res := <-resCh

		fltID := res.id
		if res.err != nil {
			err := fmt.Errorf("initializing rulelist %q: %w", fltID, res.err)
			errcoll.Collect(ctx, s.errColl, s.logger, "rule-list error", err)
			s.metrics.SetFilterStatus(ctx, string(fltID), s.clock.Now(), 0, err)

			rls[fltID] = s.prevRuleList(fltID)

			continue
		}

		rls[fltID] = res.refr
	}

	return rls
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
	defer recoverAndLog(ctx, s.logger, fl.id, resCh)

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

// recoverAndLog is a deferred helper that recovers from a panic and logs the
// panic value with the given logger.  Sends the recovered value into resCh.
func recoverAndLog(ctx context.Context, l *slog.Logger, id filter.ID, resCh chan<- refrResult) {
	err := errors.FromRecovered(recover())
	if err == nil {
		return
	}

	l.ErrorContext(ctx, "recovered panic", slogutil.KeyError, err)
	slogutil.PrintStack(ctx, l, slog.LevelError)

	resCh <- refrResult{
		id:  id,
		err: err,
	}
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
