package rulelist

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
)

// Refreshable is a refreshable DNS request and response filter based on filter
// rule lists.
//
// TODO(a.garipov): Consider adding a separate version that uses a single engine
// for multiple rule lists and using it to optimize the filtering using default
// filtering groups.
type Refreshable struct {
	*baseFilter

	logger *slog.Logger

	// mu protects [filter.engine].
	//
	// Do not add it to [filter], because the latter is used in [Immutable],
	// where serialization of access is not required.
	mu *sync.RWMutex

	// refr contains data for refreshing the filter.
	refr *refreshable.Refreshable
}

// NewRefreshable returns a new refreshable DNS request and response filter
// based on the provided rule list.  c must be non-nil.  c.URL should be an
// HTTP(S) URL.  The initial refresh should be called explicitly if necessary.
func NewRefreshable(c *refreshable.Config, cache ResultCache) (f *Refreshable, err error) {
	f = &Refreshable{
		baseFilter: newBaseFilter(nil, c.ID, "", cache),
		logger:     c.Logger,
		mu:         &sync.RWMutex{},
	}

	if strings.EqualFold(c.URL.Scheme, urlutil.SchemeFile) {
		return nil, fmt.Errorf("unsupported url %q", c.URL)
	}

	f.refr, err = refreshable.New(&refreshable.Config{
		Logger:    c.Logger,
		URL:       c.URL,
		ID:        c.ID,
		CachePath: c.CachePath,
		Staleness: c.Staleness,
		Timeout:   c.Timeout,
		MaxSize:   c.MaxSize,
	})
	if err != nil {
		return nil, fmt.Errorf("creating refreshable: %w", err)
	}

	return f, nil
}

// NewFromString returns a new DNS request and response filter using the
// provided rule text and IDs.
//
// TODO(a.garipov):  Only used in tests.  Consider removing later.
func NewFromString(
	rulesData string,
	id filter.ID,
	svcID filter.BlockedServiceID,
	cache ResultCache,
) (f *Refreshable) {
	return &Refreshable{
		mu:         &sync.RWMutex{},
		baseFilter: newBaseFilter([]byte(rulesData), id, svcID, cache),
	}
}

// SetURLFilterResult applies the DNS filtering engine and sets the values in
// res if any have matched.  ok is true if there is a match.  req and res must
// not be nil.
func (f *Refreshable) SetURLFilterResult(
	ctx context.Context,
	req *urlfilter.DNSRequest,
	res *urlfilter.DNSResult,
) (ok bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.baseFilter.SetURLFilterResult(ctx, req, res)
}

// Refresh reloads the rule list data.  If acceptStale is true, do not try to
// load the list from its URL when there is already a file in the cache
// directory, regardless of its staleness.
func (f *Refreshable) Refresh(ctx context.Context, acceptStale bool) (err error) {
	rulesData, err := f.refr.Refresh(ctx, acceptStale)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	lists := []filterlist.Interface{
		filterlist.NewBytes(&filterlist.BytesConfig{
			RulesText:      rulesData,
			IgnoreCosmetic: true,
		}),
	}

	s, err := filterlist.NewRuleStorage(lists)
	if err != nil {
		return fmt.Errorf("%s: creating rule storage: %w", f.id, err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.cache.Clear()

	f.engine = urlfilter.NewDNSEngine(s)

	f.logger.InfoContext(ctx, "reset rules", "num", f.engine.RulesCount)

	return nil
}

// RulesCount returns the number of rules in the filter's engine.
func (f *Refreshable) RulesCount() (n int) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.baseFilter.RulesCount()
}
