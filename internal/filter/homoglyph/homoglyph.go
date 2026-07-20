// Package homoglyph implements the IDN homograph filter.
package homoglyph

import (
	"context"
	"log/slog"
	"net/http/cookiejar"
	"slices"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdalg"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/composite"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/logutil/optslog"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"golang.org/x/net/idna"
)

// IDPrefix is a prefix for cache IDs, logging, and refreshes of homoglyph
// filters.
const IDPrefix = "filters/homoglyph"

// Filter is a homoglyph filter based on [UTR #39] confusable detection.
//
// [UTR #39]: https://unicode.org/reports/tr39/#Confusable_Detection
type Filter struct {
	// indexMu protects exceptions and index.
	indexMu    *sync.RWMutex
	exceptions *container.MapSet[string]
	index      skelIndex

	skelConstructor  *agdalg.SkeletonConstructor
	cloner           *dnsmsg.Cloner
	logger           *slog.Logger
	replCons         *filter.ReplacedResultConstructor
	clock            timeutil.Clock
	errColl          errcoll.Interface
	metrics          filter.Metrics
	publicSuffixList cookiejar.PublicSuffixList
	resCache         agdcache.Interface[rulelist.CacheKey, filter.Result]
	storage          filterindex.Storage
	cachePath        string
	id               filter.ID
	staleness        time.Duration
}

// skelIndex is used to optimize the filtering by having domain data mapped to
// their confusable skeletons.  Each entry must contain at least one element,
// each element must be a valid non-empty domain name.  The number of domains
// having the same skeleton is expected to be relatively low, so a slice is used
// for the value type.
type skelIndex map[string][]string

// New returns a new *Filter ready for an initial refresh with
// [Filter.RefreshInitial].  c must be valid and must not be modified after the
// call.
func New(c *Config) (f *Filter) {
	resCache := agdcache.NewLRU[rulelist.CacheKey, filter.Result](&agdcache.LRUConfig{
		Count: c.CacheCount,
	})

	skelCons := agdalg.NewSkeletonConstructor(netutil.MaxDomainNameLen, netutil.MaxDomainNameLen)

	c.CacheManager.Add(IDPrefix, resCache)

	f = &Filter{
		indexMu:          &sync.RWMutex{},
		skelConstructor:  skelCons,
		cloner:           c.Cloner,
		logger:           c.Logger,
		replCons:         c.ReplacedResultConstructor,
		clock:            c.Clock,
		errColl:          c.ErrColl,
		metrics:          c.Metrics,
		publicSuffixList: c.PublicSuffixList,
		resCache:         resCache,
		storage:          c.Storage,
		cachePath:        c.CachePath,
		id:               c.ResultListID,
		staleness:        c.Staleness,
	}

	return f
}

// type check
var _ composite.RequestFilter = (*Filter)(nil)

// FilterRequest implements the [composite.RequestFilter] interface for *Filter.
// It blocks the request if the host is a IDN homograph equivalent of a
// protected domain.
func (f *Filter) FilterRequest(
	ctx context.Context,
	req *filter.Request,
) (r filter.Result, err error) {
	exceptions, idx := f.indexData()
	if len(idx) == 0 {
		return nil, nil
	}

	qt := req.QType
	fam, ok := filter.IsFilterable(qt)
	if !ok {
		return nil, nil
	}

	host := req.Host
	// TODO(e.burkov):  Put the Unicode version of the domain to the request
	// info, so that it can be used by other filters and in logging.
	host, err = idna.ToUnicode(host)
	if err != nil {
		optslog.Trace2(
			ctx,
			f.logger,
			"converting to unicode; skipping",
			"host", req.Host,
			slogutil.KeyError, err,
		)

		return nil, nil
	}

	etld1, err := agdnet.EffectiveTLDPlusOne(f.publicSuffixList, host)
	if err != nil {
		optslog.Trace2(
			ctx,
			f.logger,
			"domain is not etld+1; skipping",
			"domain", host,
			slogutil.KeyError, err,
		)

		return nil, nil
	}

	// Check cache first.
	cl := req.QClass
	cacheKey := rulelist.NewCacheKey(etld1, qt, cl, false)

	return f.matchWithCache(req, cacheKey, etld1, exceptions, idx, fam)
}

// matchWithCache checks the cache and matches the domain against protected
// domains, returning the appropriate result.  All arguments must not be nil.
func (f *Filter) matchWithCache(
	req *filter.Request,
	cacheKey rulelist.CacheKey,
	domain string,
	exceptions *container.MapSet[string],
	idx skelIndex,
	family netutil.AddrFamily,
) (r filter.Result, err error) {
	item, ok := f.resCache.Get(cacheKey)
	if ok {
		return filter.CloneModifiedResult(item, req.DNS, f.cloner), nil
	}

	if exceptions.Has(domain) {
		f.resCache.Set(cacheKey, nil)

		return nil, nil
	}

	matched := f.matchProtectedDomain(domain, idx)
	if matched == "" {
		f.resCache.Set(cacheKey, nil)

		return nil, nil
	}

	r, err = f.replCons.New(req, f.id, matched, family)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	filter.SetModifiedResultInCache(f.resCache, cacheKey, r, f.cloner)

	return r, nil
}

// matchProtectedDomain checks if etld1 is a IDN homograph equivalent of any
// protected domain.  It returns the matched protected domain or an empty
// string.
func (f *Filter) matchProtectedDomain(etld1 string, idx skelIndex) (matched filter.RuleText) {
	confusables, ok := idx[f.skelConstructor.Skeleton(etld1)]
	if !ok || slices.Contains(confusables, etld1) {
		// No protected domains with the same skeleton, or the domain is a
		// protected domain itself.
		return ""
	}

	// The domain is a homograph of at least one protected domain.
	//
	// TODO(e.burkov):  It seems reasonable to support multiple matches, as
	// several filters already intend the same protected domain to be blocked by
	// different rules.
	return filter.RuleText(confusables[0])
}

// indexData returns the current index data.
func (f *Filter) indexData() (exceptions *container.MapSet[string], idx skelIndex) {
	f.indexMu.RLock()
	defer f.indexMu.RUnlock()

	return f.exceptions, f.index
}

// setIndexData sets the current index data from idx.  idx must not be nil.
func (f *Filter) setIndexData(ctx context.Context, idx *filterindex.Homoglyph) {
	exceptions := container.NewMapSet[string]()
	for _, exc := range idx.Exceptions {
		exceptions.Add(exc.Domain)
	}

	index := skelIndex{}
	for _, pd := range idx.Domains {
		skel := f.skelConstructor.Skeleton(pd.Domain)
		if skel == "" {
			// TODO(e.burkov):  Report to Sentry?
			f.logger.DebugContext(ctx, "domain has empty skeleton; skipping", "domain", pd.Domain)

			continue
		}

		index[skel] = append(index[skel], pd.Domain)
	}

	f.indexMu.Lock()
	defer f.indexMu.Unlock()

	f.exceptions, f.index = exceptions, index
}
