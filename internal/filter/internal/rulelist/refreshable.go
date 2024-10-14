package rulelist

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
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
	*filter

	logger *slog.Logger

	// mu protects filter.engine.
	mu *sync.RWMutex

	// refr contains data for refreshing the filter.
	refr *internal.Refreshable
}

// NewRefreshable returns a new refreshable DNS request and response filter
// based on the provided rule list.  c must be non-nil.  c.URL should be an
// HTTP(S) URL.  The initial refresh should be called explicitly if necessary.
func NewRefreshable(c *internal.RefreshableConfig, cache ResultCache) (f *Refreshable, err error) {
	f = &Refreshable{
		logger: c.Logger,
		mu:     &sync.RWMutex{},
	}

	if c.URL.Scheme == agdhttp.SchemeFile {
		return nil, fmt.Errorf("unsupported url %q", c.URL)
	}

	f.refr, err = internal.NewRefreshable(&internal.RefreshableConfig{
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

	f.filter, err = newFilter("", c.ID, "", cache)
	if err != nil {
		// Should never happen, since text is empty.
		panic(fmt.Errorf("unexpected filter error: %w", err))
	}

	return f, nil
}

// NewFromString returns a new DNS request and response filter using the
// provided rule text and ID.
//
// TODO(a.garipov): Only used in tests.  Consider removing later.
func NewFromString(
	text string,
	id agd.FilterListID,
	svcID agd.BlockedServiceID,
	cache ResultCache,
) (f *Refreshable, err error) {
	filter, err := newFilter(text, id, svcID, cache)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return &Refreshable{
		mu:     &sync.RWMutex{},
		filter: filter,
	}, nil
}

// DNSResult returns the result of applying the urlfilter DNS filtering engine.
// If the request is not filtered, DNSResult returns nil.
func (f *Refreshable) DNSResult(
	clientIP netip.Addr,
	clientName string,
	host string,
	rrType dnsmsg.RRType,
	isAns bool,
) (res *urlfilter.DNSResult) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.filter.DNSResult(clientIP, clientName, host, rrType, isAns)
}

// Refresh reloads the rule list data.  If acceptStale is true, do not try to
// load the list from its URL when there is already a file in the cache
// directory, regardless of its staleness.
func (f *Refreshable) Refresh(ctx context.Context, acceptStale bool) (err error) {
	text, err := f.refr.Refresh(ctx, acceptStale)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	// TODO(a.garipov): Add filterlist.BytesRuleList.
	strList := &filterlist.StringRuleList{
		ID:             f.urlFilterID,
		RulesText:      text,
		IgnoreCosmetic: true,
	}

	s, err := filterlist.NewRuleStorage([]filterlist.RuleList{strList})
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

	return f.filter.RulesCount()
}
