package filter

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashstorage"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/resultcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/publicsuffix"
)

// Hash-prefix filter

// HashPrefixConfig is the hash-prefix filter configuration structure.
type HashPrefixConfig struct {
	// Hashes are the hostname hashes for this filter.
	Hashes *hashstorage.Storage

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
	// TODO(a.garipov): Currently unused.
	CacheTTL time.Duration

	// CacheSize is the size of the filter's result cache.
	CacheSize int
}

// HashPrefix is a filter that matches hosts by their hashes based on a
// hash-prefix table.
type HashPrefix struct {
	hashes   *hashstorage.Storage
	refr     *refreshableFilter
	resCache *resultcache.Cache[*ResultModified]
	resolver agdnet.Resolver
	errColl  agd.ErrorCollector
	repHost  string
}

// NewHashPrefix returns a new hash-prefix filter.  c must not be nil.
func NewHashPrefix(c *HashPrefixConfig) (f *HashPrefix, err error) {
	f = &HashPrefix{
		hashes: c.Hashes,
		refr: &refreshableFilter{
			http: agdhttp.NewClient(&agdhttp.ClientConfig{
				Timeout: defaultFilterRefreshTimeout,
			}),
			url:       c.URL,
			id:        c.ID,
			cachePath: c.CachePath,
			typ:       "hash storage",
			staleness: c.Staleness,
		},
		resCache: resultcache.New[*ResultModified](c.CacheSize),
		resolver: c.Resolver,
		errColl:  c.ErrColl,
		repHost:  c.ReplacementHost,
	}

	f.refr.resetRules = f.resetRules

	err = f.refresh(context.Background(), true)
	if err != nil {
		return nil, err
	}

	return f, nil
}

// id returns the ID of the hash storage.
func (f *HashPrefix) id() (fltID agd.FilterListID) {
	return f.refr.id
}

// type check
var _ qtHostFilter = (*HashPrefix)(nil)

// filterReq implements the qtHostFilter interface for *hashPrefixFilter.  It
// modifies the response if host matches f.
func (f *HashPrefix) filterReq(
	ctx context.Context,
	ri *agd.RequestInfo,
	req *dns.Msg,
) (r Result, err error) {
	host, qt := ri.Host, ri.QType
	cacheKey := resultcache.DefaultKey(host, qt, false)
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

	fam := netutil.AddrFamilyFromRRType(qt)
	if fam == netutil.AddrFamilyNone {
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

	ctx, cancel := context.WithTimeout(ctx, defaultResolveTimeout)
	defer cancel()

	var result *dns.Msg
	ips, err := f.resolver.LookupIP(ctx, fam, f.repHost)
	if err != nil {
		agd.Collectf(ctx, f.errColl, "filter %s: resolving: %w", f.id(), err)

		result = ri.Messages.NewMsgSERVFAIL(req)
	} else {
		result, err = ri.Messages.NewIPRespMsg(req, ips...)
		if err != nil {
			return nil, fmt.Errorf("filter %s: creating modified result: %w", f.id(), err)
		}
	}

	rm = &ResultModified{
		Msg:  result,
		List: f.id(),
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

// updateCacheSizeMetrics updates cache size metrics.
func (f *HashPrefix) updateCacheSizeMetrics(size int) {
	switch id := f.id(); id {
	case agd.FilterListIDSafeBrowsing:
		metrics.HashPrefixFilterSafeBrowsingCacheSize.Set(float64(size))
	case agd.FilterListIDAdultBlocking:
		metrics.HashPrefixFilterAdultBlockingCacheSize.Set(float64(size))
	default:
		panic(fmt.Errorf("unsupported FilterListID %s", id))
	}
}

// updateCacheLookupsMetrics updates cache lookups metrics.
func (f *HashPrefix) updateCacheLookupsMetrics(hit bool) {
	var hitsMetric, missesMetric prometheus.Counter
	switch id := f.id(); id {
	case agd.FilterListIDSafeBrowsing:
		hitsMetric = metrics.HashPrefixFilterCacheSafeBrowsingHits
		missesMetric = metrics.HashPrefixFilterCacheSafeBrowsingMisses
	case agd.FilterListIDAdultBlocking:
		hitsMetric = metrics.HashPrefixFilterCacheAdultBlockingHits
		missesMetric = metrics.HashPrefixFilterCacheAdultBlockingMisses
	default:
		panic(fmt.Errorf("unsupported FilterListID %s", id))
	}

	if hit {
		hitsMetric.Inc()
	} else {
		missesMetric.Inc()
	}
}

// name implements the qtHostFilter interface for *hashPrefixFilter.
func (f *HashPrefix) name() (n string) {
	if f == nil {
		return ""
	}

	return string(f.id())
}

// type check
var _ agd.Refresher = (*HashPrefix)(nil)

// Refresh implements the [agd.Refresher] interface for *hashPrefixFilter.
func (f *HashPrefix) Refresh(ctx context.Context) (err error) {
	return f.refresh(ctx, false)
}

// refresh reloads the hash filter data.  If acceptStale is true, do not try to
// load the list from its URL when there is already a file in the cache
// directory, regardless of its staleness.
func (f *HashPrefix) refresh(ctx context.Context, acceptStale bool) (err error) {
	return f.refr.refresh(ctx, acceptStale)
}

// resetRules resets the hosts in the index.
func (f *HashPrefix) resetRules(text string) (err error) {
	n, err := f.hashes.Reset(text)

	// Report the filter update to prometheus.
	promLabels := prometheus.Labels{
		"filter": string(f.id()),
	}

	metrics.SetStatusGauge(metrics.FilterUpdatedStatus.With(promLabels), err)

	if err != nil {
		return err
	}

	metrics.FilterUpdatedTime.With(promLabels).SetToCurrentTime()
	metrics.FilterRulesTotal.With(promLabels).Set(float64(n))

	log.Info("filter %s: reset %d hosts", f.id(), n)

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
