package typosquatting

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/requestid"
	"github.com/AdguardTeam/golibs/service"
	"github.com/google/renameio/v2"
)

// type check
var _ service.Refresher = (*Filter)(nil)

// Refresh implements the [service.Refresher] interface for *Filter.
func (f *Filter) Refresh(ctx context.Context) (err error) {
	return f.refresh(ctx, false)
}

// RefreshInitial loads the content of the index, using cached files if any,
// regardless of their staleness.
func (f *Filter) RefreshInitial(ctx context.Context) (err error) {
	return f.refresh(ctx, true)
}

// refresh reloads the typosquatting-filter data.  If acceptStale is true,
// refresh doesn't try to load the data from the gRPC backend when there is
// already a file in the cache directory, regardless of its staleness.
func (f *Filter) refresh(ctx context.Context, acceptStale bool) (err error) {
	now := f.clock.Now()

	var ruleCount uint64
	defer func() { f.metrics.SetStatus(ctx, string(f.id), now, ruleCount, err) }()

	_, ok := requestid.IDFromContext(ctx)
	if !ok {
		ctx = requestid.ContextWithRequestID(ctx, requestid.New())
	}

	var idx *filterindex.Typosquatting
	cachedIdx, err := f.refreshFromFile(now, acceptStale)
	if err != nil {
		errcoll.Collect(ctx, f.errColl, f.logger, "refreshing typosquatting index from cache", err)
	} else if cachedIdx != nil {
		f.logger.InfoContext(ctx, "using cached data from file", "path", f.cachePath)

		idx, err = cachedIdx.toInternal()
		if err != nil {
			errcoll.Collect(ctx, f.errColl, f.logger, "converting cached typosquatting index", err)
		}
	}

	if idx == nil {
		idx, err = f.indexFromStorage(ctx)
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return err
		}
	}

	if idx == nil {
		return errors.Error("found no index in cache or storage")
	}

	f.setIndexData(idx)
	ruleCount = uint64(len(idx.Domains) + len(idx.Exceptions))

	if ruleCount == 0 {
		f.logger.WarnContext(ctx, "typosquatting index is empty")
	}

	return nil
}

// indexFromStorage retrieves the typosquatting-filter index from f.storage and
// caches it.  idx may be nil even if err is nil.
func (f *Filter) indexFromStorage(ctx context.Context) (idx *filterindex.Typosquatting, err error) {
	f.logger.InfoContext(ctx, "refreshing from storage")

	idx, err = f.storage.Typosquatting(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting index from storage: %w", err)
	}

	cachedIdx := newIndexCache(idx)

	// TODO(a.garipov):  Consider refactoring file handling and using [io.Copy].
	b, err := json.Marshal(cachedIdx)
	if err != nil {
		errcoll.Collect(ctx, f.errColl, f.logger, "encoding new typosquatting index", err)

		return idx, nil
	}

	err = renameio.WriteFile(f.cachePath, b, agd.PermFileDefault)
	if err != nil {
		errcoll.Collect(ctx, f.errColl, f.logger, "writing new typosquatting index", err)

		return idx, nil
	}

	return idx, nil
}

// refreshFromFile loads the data from the cache path if the file's mtime shows
// that it's still fresh relative to updTime.  If acceptStale is true, and the
// file exists, the data is read from there regardless of its staleness.
func (f *Filter) refreshFromFile(updTime time.Time, acceptStale bool) (idx *indexCache, err error) {
	b, err := refreshable.DataFromFile(f.cachePath, updTime, f.staleness, acceptStale)
	if err != nil {
		return nil, fmt.Errorf("refreshing from file %q: %w", f.cachePath, err)
	}

	if b == nil {
		return nil, nil
	}

	idx = &indexCache{}
	err = json.Unmarshal(b, idx)
	if err != nil {
		return nil, fmt.Errorf("decoding file %q: %w", f.cachePath, err)
	}

	return idx, nil
}
