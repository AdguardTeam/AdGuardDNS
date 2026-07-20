package ruleliststorage

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path"
	"path/filepath"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/google/renameio/v2"
)

// Refresh implements the [Storage] interface for *Default.
func (s *Default) Refresh(ctx context.Context) (err error) {
	s.logger.InfoContext(ctx, "refresh started")
	defer s.logger.InfoContext(ctx, "refresh finished")

	err = s.refresh(ctx, false)
	if err != nil {
		errcoll.Collect(ctx, s.errColl, s.logger, "refresh", err)
	}

	return err
}

// RefreshInitial loads the content of the storage, using cached files if any,
// regardless of their staleness.
func (s *Default) RefreshInitial(ctx context.Context) (err error) {
	s.logger.InfoContext(ctx, "initial refresh started")
	defer s.logger.InfoContext(ctx, "initial refresh finished")

	err = s.refresh(ctx, true)
	if err != nil {
		return fmt.Errorf("refreshing rule list storage initially: %w", err)
	}

	return nil
}

// refresh refreshes the rule lists.  If acceptStale is true, the cache files
// are used regardless of their staleness.
func (s *Default) refresh(ctx context.Context, acceptStale bool) (err error) {
	var prevIDs []string
	prevIDs = s.appendIDStrs(prevIDs)

	newRuleLists, err := s.loadRuleLists(ctx, acceptStale)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	s.resetRuleLists(newRuleLists)

	newIDs := make([]string, 0, len(prevIDs))
	newIDs = s.appendIDStrs(newIDs)

	prevIDSet := container.NewSortedSliceSet(prevIDs...)
	newIDSet := container.NewSortedSliceSet(newIDs...)

	deletedIDs := difference(prevIDSet, newIDSet)
	if deletedIDs.Len() > 0 {
		s.logger.InfoContext(ctx, "deleting removed filters form metrics", "ids", deletedIDs)
	}

	s.metrics.Delete(ctx, deletedIDs.Values())

	return nil
}

// appendIDStrs appends the IDs of all filters in the storage as strings to orig
// and returns it.
func (s *Default) appendIDStrs(orig []string) (res []string) {
	s.ruleListsMu.RLock()
	defer s.ruleListsMu.RUnlock()

	res = orig
	for id := range s.ruleLists {
		res = append(res, string(id))
	}

	return res
}

// difference returns a set which contains all values in a that are not in b.
// It changes a in-place.
//
// TODO(a.garipov):  Consider moving to golibs.
func difference[
	T cmp.Ordered,
](a, b *container.SortedSliceSet[T]) (diff *container.SortedSliceSet[T]) {
	// TODO(a.garipov):  Improve container.SortedSliceSet to not panic on
	// delete.
	if a == nil {
		return nil
	}

	for v := range b.Range {
		a.Delete(v)
	}

	return a
}

// loadRuleLists loads the rule-lists from the storage.  If acceptStale is true,
// the cache files are used regardless of their staleness.
func (s *Default) loadRuleLists(ctx context.Context, acceptStale bool) (rls ruleLists, err error) {
	ctx = agd.EnsureContextRequestID(ctx)

	idx := s.idxCacheFromFile(ctx, acceptStale)
	if idx == nil || len(idx.Filters) == 0 {
		s.logger.InfoContext(ctx, "no data from file", "path", s.indexCachePath)

		idx, err = s.indexFromStorage(ctx)
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return nil, err
		}
	}

	if idx == nil || len(idx.Filters) == 0 {
		return nil, errors.Error("found no index in cache or storage")
	}

	newRuleLists, err := s.refreshRuleLists(ctx, idx.Filters, acceptStale)
	if err != nil {
		return nil, fmt.Errorf("refreshing rule lists: %w", err)
	}

	s.logger.InfoContext(ctx, "compiled lists", "num_lists", len(newRuleLists))

	return newRuleLists, nil
}

// idxCacheFromFile returns the rule-list cache from the cache file, if any.
// All errors are logged and collected.  idx may be nil.
func (s *Default) idxCacheFromFile(
	ctx context.Context,
	acceptStale bool,
) (idx *filterindex.Rulelist) {
	cachedIdx, err := s.refreshFromCacheFile(s.clock.Now(), acceptStale)
	if err != nil {
		errcoll.Collect(ctx, s.errColl, s.logger, "refreshing rule list index from cache", err)
	} else if cachedIdx == nil {
		return nil
	}

	s.logger.InfoContext(ctx, "converting cached data from file", "path", s.indexCachePath)

	idx, err = cachedIdx.toInternal()
	if err != nil {
		errcoll.Collect(ctx, s.errColl, s.logger, "converting cached rule list index", err)
	}

	return idx
}

// indexFromStorage retrieves the rule list filter index and caches it.  idx may
// be nil even if err is nil.
func (s *Default) indexFromStorage(ctx context.Context) (idx *filterindex.Rulelist, err error) {
	s.logger.InfoContext(ctx, "refreshing from storage")

	idx, err = s.indexStorage.Rulelist(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting index from storage: %w", err)
	}

	if idx == nil {
		return nil, nil
	}

	cachedIdx := newIndexCache(idx)
	b, err := json.Marshal(cachedIdx)
	if err != nil {
		errcoll.Collect(ctx, s.errColl, s.logger, "encoding new rule list index", err)

		return idx, nil
	}

	err = renameio.WriteFile(s.indexCachePath, b, agd.PermFileDefault)
	if err != nil {
		errcoll.Collect(ctx, s.errColl, s.logger, "writing new rule list index", err)
	}

	return idx, nil
}

// refreshFromCacheFile loads the data from the cache path if the file's mtime
// shows that it's still fresh relative to updTime.  If acceptStale is true, and
// the file exists, the data is read from there regardless of its staleness.
func (s *Default) refreshFromCacheFile(
	updTime time.Time,
	acceptStale bool,
) (idx *indexCache, err error) {
	b, err := refreshable.DataFromFile(s.indexCachePath, updTime, s.staleness, acceptStale)
	if err != nil {
		return nil, fmt.Errorf("refreshing from file %q: %w", s.indexCachePath, err)
	}

	if b == nil {
		return nil, nil
	}

	idx = &indexCache{}
	err = json.Unmarshal(b, idx)
	if err != nil {
		return nil, fmt.Errorf("decoding file %q: %w", s.indexCachePath, err)
	}

	return idx, nil
}

// refrResult is a result of refreshing a single rule list.
type refrResult struct {
	// refr is a refreshable filter created from the provided data from index.
	// It must not be nil if err is nil.
	refr *rulelist.Refreshable

	// updTime is the update time of the rule list.
	updTime time.Time

	// err is a non-nil error if refreshing the rule list failed.
	err error

	// id is the ID of the rule list.
	id filter.ID
}

// refreshRuleLists concurrently handles the given filtersData.  Returns a map
// of new initialized and refreshed rule lists.
func (s *Default) refreshRuleLists(
	ctx context.Context,
	filtersData map[filter.ID]*filterindex.RulelistFilter,
	acceptStale bool,
) (rls ruleLists, err error) {
	lenFls := len(filtersData)

	resCh := make(chan refrResult, lenFls)
	for id, fl := range filtersData {
		go s.refreshRuleList(ctx, id, fl, acceptStale, resCh)
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

// needsUpdate returns true if the provided rule list should be refreshed,
// returns false and the previous version of the rule list if it should not be
// refreshed.  fl must not be nil.
func (s *Default) needsUpdate(
	id filter.ID,
	fl *filterindex.RulelistFilter,
) (ok bool, rl *ruleListData) {
	prev := s.prevRuleList(id)
	if prev == nil {
		return true, nil
	}

	return fl.UpdateTime.After(prev.updTime), prev
}

// resultRuleList returns a result rule list data with the refreshable and it's
// update time.  In case of error, it returns the previous version of the rule
// list and logs the error.
func (s *Default) resultRuleList(ctx context.Context, res refrResult) (rl *ruleListData) {
	fltID := res.id

	if res.err != nil {
		err := fmt.Errorf("initializing rule list %q: %w", fltID, res.err)
		errcoll.Collect(ctx, s.errColl, s.logger, "rule list error", err)
		s.metrics.SetStatus(ctx, &filter.StatusUpdate{
			Error: err,
			ID:    string(fltID),
		})

		return s.prevRuleList(fltID)
	}

	return &ruleListData{
		refr:    res.refr,
		updTime: res.updTime,
	}
}

// prevRuleList returns the previous version of the rule list data, if there is
// one.
func (s *Default) prevRuleList(id filter.ID) (rl *ruleListData) {
	s.ruleListsMu.RLock()
	defer s.ruleListsMu.RUnlock()

	if d, ok := s.ruleLists[id]; ok {
		return d
	}

	return nil
}

// refreshRuleList creates a [rulelist.Refreshable] from the data loaded with
// fl.  It also adds the cache to the cache manager.  It is intended to be
// used as a goroutine.  fl must not be nil.
func (s *Default) refreshRuleList(
	ctx context.Context,
	id filter.ID,
	fl *filterindex.RulelistFilter,
	acceptStale bool,
	resCh chan<- refrResult,
) {
	res := refrResult{
		id: id,
	}
	defer func() { resCh <- res }()

	defer s.recoverAndSetResultErr(ctx, &res)

	shouldUpdate, prev := s.needsUpdate(res.id, fl)
	if !shouldUpdate && prev != nil {
		res.refr = prev.refr
		res.updTime = prev.updTime

		s.logger.Log(ctx, slogutil.LevelTrace, "using previous rule list", "id", id)

		return
	}

	s.logger.DebugContext(ctx, "refreshing rule list", "id", id)

	// TODO(d.kolyshev):  Inspect if the existing refreshable can be reused.
	rl, err := s.newRuleListRefreshable(id, fl)
	if err != nil {
		res.err = fmt.Errorf("creating rule list: %w", err)

		return
	}

	err = rl.Refresh(ctx, acceptStale)
	if err != nil {
		res.err = fmt.Errorf("refreshing rule list: %w", err)

		return
	}

	s.metrics.SetStatus(ctx, &filter.StatusUpdate{
		Error:      nil,
		UpdateTime: s.clock.Now(),
		ID:         string(id),
		RuleCount:  rl.RulesCount(),
		SizeBytes:  rl.RulesSize(),
	})

	res.refr = rl
	res.updTime = fl.UpdateTime

	s.logger.DebugContext(ctx, "rule list refreshed successfully", "id", id)
}

// recoverAndSetResultErr is a deferred helper that recovers from panic, logs
// the error, and sets it in res.  res must not be nil.
func (s *Default) recoverAndSetResultErr(ctx context.Context, res *refrResult) {
	err := errors.FromRecovered(recover())
	if err == nil {
		return
	}

	s.logger.ErrorContext(ctx, "recovered panic", slogutil.KeyError, err)
	slogutil.PrintStack(ctx, s.logger, slog.LevelError)

	res.err = err
}

// newRuleListRefreshable returns a new rule list for the given index data.  fl
// must not be nil.
func (s *Default) newRuleListRefreshable(
	id filter.ID,
	fl *filterindex.RulelistFilter,
) (f *rulelist.Refreshable, err error) {
	fltIDStr := string(id)

	cacheID := path.Join(cachePrefixRuleList, fltIDStr)
	cache := rulelist.NewManagedResultCache(
		s.cacheManager,
		cacheID,
		s.resCacheCount,
		s.cacheEnabled,
	)

	return rulelist.NewRefreshable(&refreshable.Config{
		Clock:     s.clock,
		Logger:    s.baseLogger.With(slogutil.KeyPrefix, cacheID),
		URL:       fl.DownloadURL,
		ID:        id,
		CachePath: filepath.Join(s.cacheDir, fltIDStr),
		Staleness: s.staleness,
		Timeout:   s.refreshTimeout,
		MaxSize:   s.maxSize,
	}, cache)
}

// resetRuleLists replaces the storage's rule lists.
func (s *Default) resetRuleLists(rls ruleLists) {
	s.ruleListsMu.Lock()
	defer s.ruleListsMu.Unlock()

	s.ruleLists = rls
}
