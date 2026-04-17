// Package typosquatting implements the typosquatting filter.
package typosquatting

import (
	"context"
	"log/slog"
	"math"
	"net/http/cookiejar"
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
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// IDPrefix is a prefix for cache IDs, logging, and refreshes of typosquatting
// filters.
const IDPrefix = "filters/typosquatting"

// Filter is a typosquatting filter based on Damerau–Levenshtein distance.
type Filter struct {
	// indexDataMu protects exceptions and protectedByLen.
	indexDataMu    *sync.RWMutex
	exceptions     *container.MapSet[string]
	protectedByLen lenIndex

	calculator       *agdalg.DamerauLevenshteinCalculator
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

// lenIndex is used to optimize the filtering by having domain data mapped to
// the lengths for which they are valid.
type lenIndex map[int][]*filterindex.TyposquattingProtectedDomain

// defaultInitCalcLen is the default initial length for the Damerau–Levenshtein
// calculator's internal buffers.
const defaultInitCalcLen = netutil.MaxDomainNameLen

// New returns a new *Filter ready for an initial refresh with
// [Filter.RefreshInitial].  c must be valid and must not be modified after the
// call.
func New(c *Config) (f *Filter) {
	resCache := agdcache.NewLRU[rulelist.CacheKey, filter.Result](&agdcache.LRUConfig{
		Count: c.CacheCount,
	})

	c.CacheManager.Add(IDPrefix, resCache)

	f = &Filter{
		indexDataMu: &sync.RWMutex{},

		calculator:       agdalg.NewDamerauLevenshteinCalculator(defaultInitCalcLen),
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
// It blocks the request if the host is a typosquatting attempt of a protected
// domain.
func (f *Filter) FilterRequest(
	ctx context.Context,
	req *filter.Request,
) (r filter.Result, err error) {
	host, qt, cl := req.Host, req.QType, req.QClass

	exceptions, protectedByLen := f.indexData()
	if len(protectedByLen) == 0 {
		return nil, nil
	}

	fam, ok := filter.IsFilterable(qt)
	if !ok {
		return nil, nil
	}

	etld1, err := agdnet.EffectiveTLDPlusOne(f.publicSuffixList, host)
	if err != nil {
		etld1 = host
	}

	// Check cache first.
	cacheKey := rulelist.NewCacheKey(etld1, qt, cl, false)
	item, ok := f.resCache.Get(cacheKey)
	if ok {
		return filter.CloneModifiedResult(item, req.DNS, f.cloner), nil
	}

	if exceptions.Has(etld1) {
		f.resCache.Set(cacheKey, nil)

		return nil, nil
	}

	matched := f.matchProtectedDomain(etld1, protectedByLen)
	if matched == nil {
		f.resCache.Set(cacheKey, nil)

		return nil, nil
	}

	r, err = f.replCons.New(req, f.id, filter.RuleText(matched.Domain), fam)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	filter.SetModifiedResultInCache(f.resCache, cacheKey, r, f.cloner)

	return r, nil
}

// matchProtectedDomain checks if etld1 is a typosquatting attempt of any
// protected domain.  protectedByLen is the index used for optimization.  It
// returns the matched protected domain or nil.
func (f *Filter) matchProtectedDomain(etld1 string, protectedByLen lenIndex) (
	matched *filterindex.TyposquattingProtectedDomain,
) {
	var minDist uint = math.MaxUint
	for _, pd := range protectedByLen[len(etld1)] {
		dist := f.calculator.Distance(etld1, pd.Domain)

		if dist == 0 {
			// Exact match, don't block.
			return nil
		}

		if dist > 0 && dist <= pd.Distance && dist < minDist {
			// Found a match within the allowed distance.
			matched = pd
			minDist = dist
		}
	}

	return matched
}

// indexData returns the current index data.
func (f *Filter) indexData() (exceptions *container.MapSet[string], protectedByLen lenIndex) {
	f.indexDataMu.RLock()
	defer f.indexDataMu.RUnlock()

	return f.exceptions, f.protectedByLen
}

// setIndexData sets the current index data from idx.  idx must not be nil.
func (f *Filter) setIndexData(idx *filterindex.Typosquatting) {
	exceptions := container.NewMapSet[string]()
	for _, exc := range idx.Exceptions {
		exceptions.Add(exc.Domain)
	}

	protectedByLen := lenIndex{}
	for _, pd := range idx.Domains {
		l := len(pd.Domain)
		minLen, maxLen := max(0, l-int(pd.Distance)), l+int(pd.Distance)

		for i := minLen; i <= maxLen; i++ {
			protectedByLen[i] = append(protectedByLen[i], pd)
		}
	}

	f.indexDataMu.Lock()
	defer f.indexDataMu.Unlock()

	f.exceptions, f.protectedByLen = exceptions, protectedByLen
}
