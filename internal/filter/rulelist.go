package filter

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"path/filepath"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
)

// Rule List File Filter

// ruleListFilter is a DNS request and response filter based on filter rule
// lists.
//
// TODO(a.garipov): Consider adding a separate version that uses a single engine
// for multiple rule lists and using it to optimize the filtering using default
// filtering groups.
type ruleListFilter struct {
	// mu protects engine and ruleList.
	mu *sync.RWMutex

	// refr contains data for refreshing the filter.
	refr *refreshableFilter

	// engine is the DNS filtering engine.
	engine *urlfilter.DNSEngine

	// ruleList is the filtering rule ruleList used by the engine.
	//
	// TODO(a.garipov): Consider making engines in module urlfilter closeable
	// and remove this crutch.
	ruleList filterlist.RuleList

	// svcID is the identifier of the blocked service.  It is used in the
	// filtering result as the rule when id is FilterListIDBlockedService.
	svcID agd.BlockedServiceID

	// urlFilterID is the synthetic integer identifier for the urlfilter engine.
	//
	// TODO(a.garipov): Change the type to a string in module urlfilter and
	// remove this crutch.
	urlFilterID int
}

// newRuleListFilter returns a new DNS request and response filter based on the
// provided rule list.  l must be non-nil.  The initial refresh should be called
// explicitly if necessary.
func newRuleListFilter(
	l *agd.FilterList,
	cacheDir string,
) (flt *ruleListFilter) {
	flt = &ruleListFilter{
		mu: &sync.RWMutex{},
		refr: &refreshableFilter{
			http: agdhttp.NewClient(&agdhttp.ClientConfig{
				Timeout: defaultTimeout,
			}),
			url:        l.URL,
			id:         l.ID,
			cachePath:  filepath.Join(cacheDir, string(l.ID)),
			typ:        "rule list",
			refreshIvl: l.RefreshIvl,
		},
		urlFilterID: newURLFilterID(),
	}

	// Do not set this in the literal above, since flt is nil there.
	flt.refr.resetRules = flt.resetRules

	return flt
}

// newRuleListFltFromStr returns a new DNS request and response filter using the
// provided rule text and ID.
func newRuleListFltFromStr(text string, id agd.FilterListID) (flt *ruleListFilter, err error) {
	flt = &ruleListFilter{
		mu: &sync.RWMutex{},
		refr: &refreshableFilter{
			id:  id,
			typ: "rule list",
		},
		urlFilterID: newURLFilterID(),
	}

	err = flt.resetRules(text)
	if err != nil {
		return nil, err
	}

	return flt, nil
}

// newURLFilterID returns a new random ID for the urlfilter DNS engine to use.
func newURLFilterID() (id int) {
	// #nosec G404 -- Do not use cryptographically random ID generation, since
	// these are only used in one place, compFilter.filterMsg, and are not used
	// in any security-sensitive context.
	//
	// Despite the fact that the type of integer filter list IDs in module
	// urlfilter is int, the module actually assumes that the ID is
	// a non-negative integer, or at least not a largely negative one.
	// Otherwise, some of its low-level optimizations seem to break.
	return int(rand.Int31())
}

// dnsResult returns the result of applying the urlfilter DNS filtering engine.
// underlying urlfilter DNS filtering engine.
func (f *ruleListFilter) dnsResult(
	cliIP netip.Addr,
	cliName string,
	host string,
	rrType dnsmsg.RRType,
	ans bool,
) (dr *urlfilter.DNSResult) {
	dnsReq := &urlfilter.DNSRequest{
		Hostname: host,
		// TODO(a.garipov): Make this a net.IP in module urlfilter.
		ClientIP:   cliIP.String(),
		ClientName: cliName,
		DNSType:    rrType,
		Answer:     ans,
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	dr, ok := f.engine.MatchRequest(dnsReq)
	if !ok && len(dr.NetworkRules) == 0 {
		return nil
	}

	return dr
}

// Close implements the io.Closer interface for *ruleListFilter.
func (f *ruleListFilter) Close() (err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err = f.ruleList.Close(); err != nil {
		return fmt.Errorf("closing rule list %q: %w", f.id(), err)
	}

	return nil
}

// id returns the ID of the rule list.
func (f *ruleListFilter) id() (fltID agd.FilterListID) {
	return f.refr.id
}

// refresh reloads the rule list data.  If acceptStale is true, do not try to
// load the list from its URL when there is already a file in the cache
// directory, regardless of its staleness.
func (f *ruleListFilter) refresh(ctx context.Context, acceptStale bool) (err error) {
	return f.refr.refresh(ctx, acceptStale)
}

// resetRules resets the filtering rules.
func (f *ruleListFilter) resetRules(text string) (err error) {
	// TODO(a.garipov): Add filterlist.BytesRuleList.
	strList := &filterlist.StringRuleList{
		ID:             f.urlFilterID,
		RulesText:      text,
		IgnoreCosmetic: true,
	}

	s, err := filterlist.NewRuleStorage([]filterlist.RuleList{strList})
	if err != nil {
		return fmt.Errorf("creating list storage: %w", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.ruleList = strList
	f.engine = urlfilter.NewDNSEngine(s)

	if f.svcID == "" {
		log.Info("filter %s: reset %d rules", f.id(), f.engine.RulesCount)
	} else {
		log.Info("filter %s/%s: reset %d rules", f.id(), f.svcID, f.engine.RulesCount)
	}

	return nil
}
