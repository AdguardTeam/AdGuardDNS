// Package domain implements a domain filter based on domain table.
package domain

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http/cookiejar"
	"net/url"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/c2h5oh/datasize"
	"github.com/miekg/dns"
)

// FilterConfig is the domain filter configuration structure.
type FilterConfig struct {
	// Logger is used for logging the operation of the filter.
	Logger *slog.Logger

	// CacheManager is the global cache manager.  CacheManager must not be nil.
	CacheManager agdcache.Manager

	// URL is the URL used to update the filter.
	URL *url.URL

	// ErrColl is used to collect non-critical and rare errors.
	ErrColl errcoll.Interface

	// DomainMetrics are the specific metrics for the domain filter.
	DomainMetrics Metrics

	// Metrics are the metrics for the domain filter.
	Metrics filter.Metrics

	// PublicSuffixList is used for obtaining public suffix for specified
	// domain.
	PublicSuffixList cookiejar.PublicSuffixList

	// CategoryID is the category identifier used for logging and error
	// reporting.
	CategoryID filter.CategoryID

	// ResultListID is the identifier of the filter list used in the request
	// filtering result.
	ResultListID filter.ID

	// CachePath is the path to the file containing the cached filtered
	// hostnames, one per line.
	CachePath string

	// Staleness is the time after which a file is considered stale.
	Staleness time.Duration

	// CacheTTL is the time-to-live value used to cache the results of the
	// filter.
	//
	// TODO(a.garipov): Currently unused.  See AGDNS-398.
	CacheTTL time.Duration

	// RefreshTimeout is the timeout for the filter update operation.
	RefreshTimeout time.Duration

	// CacheCount is the count of the elements in the filter's result cache.
	CacheCount int

	// MaxSize is the maximum size of the downloadable rule-list.
	MaxSize datasize.ByteSize

	// SubDomainNum defines how many subdomains will be checked for one domain.
	// It must be positive and fit into int.
	SubDomainNum uint
}

// Filter is a domain table based filter.
//
// TODO(f.setrakov): Consider DRYing it with the hasprefix filter.
type Filter struct {
	logger           *slog.Logger
	domains          *atomic.Pointer[container.MapSet[string]]
	refr             *refreshable.Refreshable
	subDomainsPool   *syncutil.Pool[[]string]
	errColl          errcoll.Interface
	domainMtrc       Metrics
	publicSuffixList cookiejar.PublicSuffixList
	metrics          filter.Metrics
	resCache         agdcache.Interface[rulelist.CacheKey, filter.Result]
	catID            filter.CategoryID
	resListID        filter.ID
	subDomainNum     int
}

// IDPrefix is a common prefix for cache IDs, logging, and refreshes of
// domain filters.
//
// TODO(a.garipov):  Consider better names.
const IDPrefix = "filters/domain"

// NewFilter returns a new domain filter.  It adds the cache to the cache
// manager specified in c.  c must not be nil.
func NewFilter(c *FilterConfig) (f *Filter, err error) {
	catID := c.CategoryID

	resCache := agdcache.NewLRU[rulelist.CacheKey, filter.Result](&agdcache.LRUConfig{
		Count: c.CacheCount,
	})

	c.CacheManager.Add(path.Join(IDPrefix, string(catID)), resCache)

	f = &Filter{
		logger:  c.Logger,
		domains: &atomic.Pointer[container.MapSet[string]]{},
		errColl: c.ErrColl,
		// #nosec G115 -- Assume that c.SubDomainNum is always less then or
		// equal to 63.
		//
		// TODO(f.setrakov): Validate c.SubDomainsNum.
		subDomainsPool:   syncutil.NewSlicePool[string](int(c.SubDomainNum)),
		domainMtrc:       c.DomainMetrics,
		metrics:          c.Metrics,
		publicSuffixList: c.PublicSuffixList,
		resCache:         resCache,
		catID:            catID,
		resListID:        c.ResultListID,
		// #nosec G115 -- The value is a constant less than int accommodates.
		subDomainNum: int(c.SubDomainNum),
	}

	f.refr, err = refreshable.New(&refreshable.Config{
		Logger:    f.logger,
		URL:       c.URL,
		ID:        filter.ID(catID),
		CachePath: c.CachePath,
		Staleness: c.Staleness,
		Timeout:   c.RefreshTimeout,
		MaxSize:   c.MaxSize,
	})
	if err != nil {
		return nil, fmt.Errorf("creating refreshable: %w", err)
	}

	return f, nil
}

// FilterRequest implements the [composite.RequestFilter] interface for *Filter.
// It blocks the request if host matches f.
func (f *Filter) FilterRequest(
	ctx context.Context,
	req *filter.Request,
) (r filter.Result, err error) {
	host, qt, cl := req.Host, req.QType, req.QClass

	cacheKey := rulelist.NewCacheKey(host, qt, cl, false)
	item, ok := f.resCache.Get(cacheKey)
	f.domainMtrc.IncrementLookups(ctx, f.catID, ok)
	if ok {
		return item, nil
	}

	if !isFilterable(qt) {
		return nil, nil
	}

	var matched string
	subPtr := f.subDomainsPool.Get()
	defer f.subDomainsPool.Put(subPtr)

	*subPtr = agdnet.AppendSubdomains((*subPtr)[:0], host, f.subDomainNum, f.publicSuffixList)

	domains := *f.domains.Load()
	for _, s := range *subPtr {
		if domains.Has(s) {
			matched = s

			break
		}
	}

	if matched == "" {
		f.resCache.Set(cacheKey, nil)

		return nil, nil
	}

	r = &filter.ResultBlocked{
		List: f.resListID,
		Rule: filter.RuleText(f.catID),
	}

	f.resCache.Set(cacheKey, r)

	f.domainMtrc.UpdateCacheSize(ctx, f.catID, f.resCache.Len())

	return r, nil
}

// isFilterable returns true if the question type is filterable.
func isFilterable(qt dnsmsg.RRType) (ok bool) {
	fam := netutil.AddrFamilyFromRRType(qt)

	return qt == dns.TypeHTTPS || fam != netutil.AddrFamilyNone
}

// type check
var _ service.Refresher = (*Filter)(nil)

// Refresh implements the [service.Refresher] interface for *Filter.
func (f *Filter) Refresh(ctx context.Context) (err error) {
	f.logger.InfoContext(ctx, "refresh started")
	defer f.logger.InfoContext(ctx, "refresh finished")

	err = f.refresh(ctx, false)
	if err != nil {
		errcoll.Collect(ctx, f.errColl, f.logger, fmt.Sprintf("refreshing %q", f.catID), err)
	}

	return err
}

// RefreshInitial loads the content of the filter, using cached files if any,
// regardless of their staleness.
func (f *Filter) RefreshInitial(ctx context.Context) (err error) {
	f.logger.InfoContext(ctx, "initial refresh started")
	defer f.logger.InfoContext(ctx, "initial refresh finished")

	err = f.refresh(ctx, true)
	if err != nil {
		return fmt.Errorf("refreshing domain filter initially: %w", err)
	}

	return nil
}

// refresh reloads and resets domain data.  If acceptStale is true, do not try
// to load the list from its URL when there is already a file in the cache
// directory, regardless of its staleness.
func (f *Filter) refresh(ctx context.Context, acceptStale bool) (err error) {
	var count int
	defer func() {
		// TODO(a.garipov):  Consider using [agdtime.Clock].
		// TODO(a.garipov):  Consider using a prefix or a label for categories.
		f.metrics.SetFilterStatus(ctx, string(f.catID), time.Now(), count, err)
	}()

	b, err := f.refr.Refresh(ctx, acceptStale)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	count, err = f.resetDomains(b)
	if err != nil {
		return fmt.Errorf("%s: resetting: %w", f.catID, err)
	}

	f.resCache.Clear()

	f.logger.InfoContext(ctx, "reset hosts", "num", count)

	return nil
}

// resetDomains populates storage with domains from domainData.
func (f *Filter) resetDomains(domainData []byte) (n int, err error) {
	next := container.NewMapSet[string]()

	sc := bufio.NewScanner(bytes.NewReader(domainData))
	for sc.Scan() {
		domain := sc.Text()
		if len(domain) == 0 || domain[0] == '#' {
			continue
		}

		next.Add(strings.ToLower(domain))
		n++
	}

	err = sc.Err()
	if err != nil {
		return 0, fmt.Errorf("scanning domains: %w", err)
	}

	f.domains.Store(next)

	return n, nil
}
