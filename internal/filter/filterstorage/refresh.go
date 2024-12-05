package filterstorage

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// type check
var _ agdservice.Refresher = (*Default)(nil)

// Refresh implements the [agdservice.Refresher] interface for *Default.
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

	newRuleLists := make(ruleLists, len(resp.Filters))
	for _, fl := range fls {
		s.addRuleList(ctx, newRuleLists, fl, acceptStale)

		if ctxErr := ctx.Err(); ctxErr != nil {
			// If the context has already been canceled, no need to continue, as
			// the other refreshes won't be able to finish either way.
			s.logger.ErrorContext(ctx, "after refreshing lists", slogutil.KeyError, ctxErr)

			return fmt.Errorf("after refreshing rule lists: %w", ctxErr)
		}
	}

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

// addRuleList adds the data from fl to newRuleLists and handles validations and
// errors.  It also adds the cache to the cache manager.
func (s *Default) addRuleList(
	ctx context.Context,
	newRuleLists ruleLists,
	fl *indexData,
	acceptStale bool,
) {
	if _, ok := newRuleLists[fl.id]; ok {
		err := fmt.Errorf("rule-list id: %w: %q", errors.ErrDuplicated, fl.id)
		errcoll.Collect(ctx, s.errColl, s.logger, "adding rule list", err)

		return
	}

	fltIDStr := string(fl.id)
	cacheID := path.Join(cachePrefixRuleList, fltIDStr)
	cache := rulelist.NewManagedResultCache(
		s.cacheManager,
		cacheID,
		s.ruleListResCacheCount,
		s.ruleListCacheEnabled,
	)

	rl, err := rulelist.NewRefreshable(
		&refreshable.Config{
			Logger:    s.baseLogger.With(slogutil.KeyPrefix, cacheID),
			URL:       fl.url,
			ID:        fl.id,
			CachePath: filepath.Join(s.cacheDir, fltIDStr),
			Staleness: s.ruleListStaleness,
			Timeout:   s.ruleListRefreshTimeout,
			MaxSize:   s.ruleListMaxSize,
		},
		cache,
	)
	if err != nil {
		s.reportRuleListError(ctx, fl, fmt.Errorf("creating rulelist: %w", err))
		s.setPrevRuleList(newRuleLists, fl.id)

		return
	}

	err = rl.Refresh(ctx, acceptStale)
	if err != nil {
		s.reportRuleListError(ctx, fl, fmt.Errorf("refreshing rulelist: %w", err))
		s.setPrevRuleList(newRuleLists, fl.id)

		return
	}

	newRuleLists[fl.id] = rl

	s.metrics.SetFilterStatus(ctx, fltIDStr, s.clock.Now(), rl.RulesCount(), nil)
}

// reportRuleListError reports the error encountered when refreshing a rule-list
// filter.
func (s *Default) reportRuleListError(ctx context.Context, fl *indexData, err error) {
	errcoll.Collect(ctx, s.errColl, s.logger, "rule-list error", err)
	s.metrics.SetFilterStatus(ctx, string(fl.id), s.clock.Now(), 0, err)
}

// setPrevRuleList adds the previous version of the filter to newRuleLists, if
// there is one.
func (s *Default) setPrevRuleList(newRuleLists ruleLists, id filter.ID) {
	s.ruleListsMu.RLock()
	defer s.ruleListsMu.RUnlock()

	if rl, ok := s.ruleLists[id]; ok {
		newRuleLists[id] = rl
	}
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
