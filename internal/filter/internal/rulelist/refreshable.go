package rulelist

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/golibs/log"
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

	// mu protects filter.engine.
	mu *sync.RWMutex

	// refr contains data for refreshing the filter.
	refr *internal.Refreshable
}

// NewRefreshable returns a new refreshable DNS request and response filter
// based on the provided rule list.  l must be non-nil.  The initial refresh
// should be called explicitly if necessary.
func NewRefreshable(
	l *agd.FilterList,
	fileCacheDir string,
	memCacheSize int,
	useMemCache bool,
) (f *Refreshable) {
	f = &Refreshable{
		mu:   &sync.RWMutex{},
		refr: internal.NewRefreshable(l, filepath.Join(fileCacheDir, string(l.ID))),
	}

	var err error
	f.filter, err = newFilter("", l.ID, "", memCacheSize, useMemCache)
	if err != nil {
		// Should never happen, since text is empty.
		panic(fmt.Errorf("unexpected filter error: %w", err))
	}

	return f
}

// NewFromString returns a new DNS request and response filter using the
// provided rule text and ID.
//
// TODO(a.garipov): Only used in tests.  Consider removing later.
func NewFromString(
	text string,
	id agd.FilterListID,
	svcID agd.BlockedServiceID,
	memCacheSize int,
	useMemCache bool,
) (f *Refreshable, err error) {
	f = &Refreshable{
		mu: &sync.RWMutex{},
	}

	f.filter, err = newFilter(text, id, svcID, memCacheSize, useMemCache)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return f, nil
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
		return fmt.Errorf("creating rule storage: %w", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.cache.Clear()
	f.engine = urlfilter.NewDNSEngine(s)

	log.Info("%s: reset %d rules", f.id, f.engine.RulesCount)

	return nil
}

// RulesCount returns the number of rules in the filter's engine.
func (f *Refreshable) RulesCount() (n int) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.filter.RulesCount()
}
