package hashprefix

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/resultcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/publicsuffix"
)

// FilterConfig is the hash-prefix filter configuration structure.
type FilterConfig struct {
	// Hashes are the hostname hashes for this filter.
	Hashes *Storage

	// URL is the URL used to update the filter.
	URL *url.URL

	// ErrColl is used to collect non-critical and rare errors.
	ErrColl agd.ErrorCollector

	// Resolver is used to resolve hosts for the hash-prefix filter.
	Resolver agdnet.Resolver

	// ID is the ID of this hash storage for logging and error reporting.
	ID agd.FilterListID

	// CachePath is the path to the file containing the cached filtered
	// hostnames, one per line.
	CachePath string

	// ReplacementHost is the replacement host for this filter.  Queries
	// matched by the filter receive a response with the IP addresses of
	// this host.
	ReplacementHost string

	// Staleness is the time after which a file is considered stale.
	Staleness time.Duration

	// CacheTTL is the time-to-live value used to cache the results of the
	// filter.
	//
	// TODO(a.garipov): Currently unused.  See AGDNS-398.
	CacheTTL time.Duration

	// CacheSize is the size of the filter's result cache.
	CacheSize int

	// MaxSize is the maximum size in bytes of the downloadable rule-list.
	MaxSize int64
}

// Filter is a filter that matches hosts by their hashes based on a
// hash-prefix table.
type Filter struct {
	hashes   *Storage
	refr     *internal.Refreshable
	resCache *resultcache.Cache[*internal.ResultModified]
	resolver agdnet.Resolver
	errColl  agd.ErrorCollector
	id       agd.FilterListID
	repHost  string
}

// NewFilter returns a new hash-prefix filter.  c must not be nil.
func NewFilter(c *FilterConfig) (f *Filter, err error) {
	id := c.ID
	f = &Filter{
		hashes:   c.Hashes,
		resCache: resultcache.New[*internal.ResultModified](c.CacheSize),
		resolver: c.Resolver,
		errColl:  c.ErrColl,
		id:       id,
		repHost:  c.ReplacementHost,
	}

	f.refr = internal.NewRefreshable(&internal.RefreshableConfig{
		URL:       c.URL,
		ID:        id,
		CachePath: c.CachePath,
		Staleness: c.Staleness,
		// TODO(ameshkov): Consider making configurable.
		Timeout: internal.DefaultFilterRefreshTimeout,
		MaxSize: c.MaxSize,
	})

	err = f.refresh(context.Background(), true)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return f, nil
}

// type check
var _ internal.RequestFilter = (*Filter)(nil)

// FilterRequest implements the [internal.RequestFilter] interface for
// *Filter.  It modifies the response if host matches f.
func (f *Filter) FilterRequest(
	ctx context.Context,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (r internal.Result, err error) {
	host, qt, cl := ri.Host, ri.QType, ri.QClass
	cacheKey := resultcache.DefaultKey(host, qt, cl, false)
	rm, ok := f.resCache.Get(cacheKey)
	f.updateCacheLookupsMetrics(ok)
	if ok {
		if rm == nil {
			// Return nil explicitly instead of modifying CloneForReq to return
			// nil if the result is nil to avoid a “non-nil nil” value.
			return nil, nil
		}

		return rm.CloneForReq(req), nil
	}

	fam, ok := isFilterable(qt)
	if !ok {
		return nil, nil
	}

	var matched string
	sub := hashableSubdomains(host)
	for _, s := range sub {
		if f.hashes.Matches(s) {
			matched = s

			break
		}
	}

	if matched == "" {
		f.resCache.Set(cacheKey, nil)

		return nil, nil
	}

	ctx, cancel := context.WithTimeout(ctx, internal.DefaultResolveTimeout)
	defer cancel()

	result, err := f.filteredResponse(ctx, req, ri, fam)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	rm = &internal.ResultModified{
		Msg:  result,
		List: f.id,
		Rule: agd.FilterRuleText(matched),
	}

	// Copy the result to make sure that modifications to the result message
	// down the pipeline don't interfere with the cached value.
	//
	// See AGDNS-359.
	f.resCache.Set(cacheKey, rm.Clone())
	f.updateCacheSizeMetrics(f.resCache.ItemCount())

	return rm, nil
}

// ID implements the [internal.RequestFilter] interface for *Filter.
func (f *Filter) ID() (id agd.FilterListID) {
	return f.id
}

// isFilterable returns true if the question type is filterable.  If the type is
// filterable with a blocked page, fam is the address family for the IP
// addresses of the blocked page; otherwise fam is [netutil.AddrFamilyNone].
func isFilterable(qt dnsmsg.RRType) (fam netutil.AddrFamily, ok bool) {
	if qt == dns.TypeHTTPS {
		return netutil.AddrFamilyNone, true
	}

	fam = netutil.AddrFamilyFromRRType(qt)

	return fam, fam != netutil.AddrFamilyNone
}

// filteredResponse returns a filtered response.
func (f *Filter) filteredResponse(
	ctx context.Context,
	req *dns.Msg,
	ri *agd.RequestInfo,
	fam netutil.AddrFamily,
) (resp *dns.Msg, err error) {
	if fam == netutil.AddrFamilyNone {
		// This is an HTTPS query.  For them, just return NODATA or other
		// blocked response.  See AGDNS-1551.
		//
		// TODO(ameshkov): Consider putting the resolved IP addresses into hints
		// to show the blocked page here as well.
		resp, err = ri.Messages.NewBlockedRespMsg(req)
		if err != nil {
			return nil, fmt.Errorf("filter %s: creating blocked result: %w", f.id, err)
		}

		return resp, nil
	}

	ctx, cancel := context.WithTimeout(ctx, internal.DefaultResolveTimeout)
	defer cancel()

	ips, err := f.resolver.LookupNetIP(ctx, fam, f.repHost)
	if err != nil {
		agd.Collectf(ctx, f.errColl, "filter %s: resolving: %w", f.id, err)

		return ri.Messages.NewMsgSERVFAIL(req), nil
	}

	resp, err = ri.Messages.NewIPRespMsg(req, ips...)
	if err != nil {
		return nil, fmt.Errorf("filter %s: creating modified result: %w", f.id, err)
	}

	return resp, nil
}

// updateCacheSizeMetrics updates cache size metrics.
func (f *Filter) updateCacheSizeMetrics(size int) {
	switch id := f.id; id {
	case agd.FilterListIDSafeBrowsing:
		metrics.HashPrefixFilterSafeBrowsingCacheSize.Set(float64(size))
	case agd.FilterListIDAdultBlocking:
		metrics.HashPrefixFilterAdultBlockingCacheSize.Set(float64(size))
	case agd.FilterListIDNewRegDomains:
		metrics.HashPrefixFilterNewRegDomainsCacheSize.Set(float64(size))
	default:
		panic(fmt.Errorf("unsupported FilterListID %s", id))
	}
}

// updateCacheLookupsMetrics updates cache lookups metrics.
func (f *Filter) updateCacheLookupsMetrics(hit bool) {
	var hitsMetric, missesMetric prometheus.Counter
	switch id := f.id; id {
	case agd.FilterListIDSafeBrowsing:
		hitsMetric = metrics.HashPrefixFilterCacheSafeBrowsingHits
		missesMetric = metrics.HashPrefixFilterCacheSafeBrowsingMisses
	case agd.FilterListIDAdultBlocking:
		hitsMetric = metrics.HashPrefixFilterCacheAdultBlockingHits
		missesMetric = metrics.HashPrefixFilterCacheAdultBlockingMisses
	case agd.FilterListIDNewRegDomains:
		hitsMetric = metrics.HashPrefixFilterCacheNewRegDomainsHits
		missesMetric = metrics.HashPrefixFilterCacheNewRegDomainsMisses
	default:
		panic(fmt.Errorf("unsupported filter list id %s", id))
	}

	if hit {
		hitsMetric.Inc()
	} else {
		missesMetric.Inc()
	}
}

// type check
var _ agd.Refresher = (*Filter)(nil)

// Refresh implements the [agd.Refresher] interface for *hashPrefixFilter.
func (f *Filter) Refresh(ctx context.Context) (err error) {
	return f.refresh(ctx, false)
}

// refresh reloads and resets the hash-filter data.  If acceptStale is true, do
// not try to load the list from its URL when there is already a file in the
// cache directory, regardless of its staleness.
func (f *Filter) refresh(ctx context.Context, acceptStale bool) (err error) {
	text, err := f.refr.Refresh(ctx, acceptStale)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	n, err := f.hashes.Reset(text)
	fltIDStr := string(f.id)
	metrics.SetStatusGauge(metrics.FilterUpdatedStatus.WithLabelValues(fltIDStr), err)
	if err != nil {
		return fmt.Errorf("resetting: %w", err)
	}

	f.resCache.Clear()

	metrics.FilterUpdatedTime.WithLabelValues(fltIDStr).SetToCurrentTime()
	metrics.FilterRulesTotal.WithLabelValues(fltIDStr).Set(float64(n))

	log.Info("filter %s: reset %d hosts", f.id, n)

	return nil
}

// subDomainNum defines how many labels should be hashed to match against a hash
// prefix filter.
const subDomainNum = 4

// hashableSubdomains returns all subdomains that should be checked by the hash
// prefix filter.
func hashableSubdomains(domain string) (sub []string) {
	pubSuf, icann := publicsuffix.PublicSuffix(domain)
	if !icann {
		// Check the full private domain space.
		pubSuf = ""
	}

	dotsNum := 0
	i := strings.LastIndexFunc(domain, func(r rune) (ok bool) {
		if r == '.' {
			dotsNum++
		}

		return dotsNum == subDomainNum
	})
	if i != -1 {
		domain = domain[i+1:]
	}

	sub = netutil.Subdomains(domain)
	for i, s := range sub {
		if s == pubSuf {
			sub = sub[:i]

			break
		}
	}

	return sub
}
