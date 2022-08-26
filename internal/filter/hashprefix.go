package filter

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/publicsuffix"
)

// Hash Prefix Filter

// HashPrefixConfig is the hash prefix filter configuration structure.
type HashPrefixConfig struct {
	// Hashes are the hostname hashes for this filter.
	Hashes *HashStorage

	// ReplacementHost is the replacement host for this filter.  Queries
	// matched by the filter receive a response with the IP addresses of
	// this host.
	ReplacementHost string

	// CacheTTL is the time-to-live value used to cache the results of the
	// filter.
	CacheTTL time.Duration

	// CacheSize is the size of the filter's result cache.
	//
	// TODO(a.garipov): Currently unused.
	CacheSize int
}

// hashPrefixFilter is a filter that matches hosts by their hashes based on
// a hash prefix table.
type hashPrefixFilter struct {
	hashes    *HashStorage
	resCache  *resultCache
	rslvCache *resolveCache
	errColl   agd.ErrorCollector
	repHost   string
	id        agd.FilterListID
}

// newHashPrefixFilter returns a new hash prefix filter.  c must not be nil.
func newHashPrefixFilter(
	c *HashPrefixConfig,
	rslvCache *resolveCache,
	errColl agd.ErrorCollector,
	id agd.FilterListID,
) (f *hashPrefixFilter) {
	cache := &resultCache{
		cache: cache.New(c.CacheTTL, defaultResultCacheGC),
	}

	return &hashPrefixFilter{
		hashes:    c.Hashes,
		resCache:  cache,
		rslvCache: rslvCache,
		errColl:   errColl,
		repHost:   c.ReplacementHost,
		id:        id,
	}
}

// type check
var _ qtHostFilter = (*hashPrefixFilter)(nil)

// filterReq implements the qtHostFilter interface for *hashPrefixFilter.  It
// modifies the response if host matches f.
func (f *hashPrefixFilter) filterReq(
	ctx context.Context,
	ri *agd.RequestInfo,
	req *dns.Msg,
) (r Result, err error) {
	host := ri.Host
	qt := ri.QType
	r, ok := f.resCache.get(host, qt)
	f.updateCacheLookupsMetrics(ok)
	if ok {
		return r.(*ResultModified).CloneForReq(req), nil
	}

	network := dnsTypeToNetwork(qt)
	if network == "" {
		return nil, nil
	}

	var matched string
	sub := hashableSubdomains(host)
	for _, s := range sub {
		if f.hashes.hashMatches(s) {
			matched = s

			break
		}
	}

	if matched == "" {
		return nil, nil
	}

	var result *dns.Msg
	ips, err := f.rslvCache.resolve(network, f.repHost)
	if err != nil {
		agd.Collectf(ctx, f.errColl, "filter %s: resolving: %w", f.id, err)

		result = ri.Messages.NewMsgSERVFAIL(req)
	} else {
		result, err = ri.Messages.NewIPRespMsg(req, ips...)
		if err != nil {
			return nil, fmt.Errorf("filter %s: creating modified result: %w", f.id, err)
		}
	}

	rm := &ResultModified{
		Msg:  result,
		List: f.id,
		Rule: agd.FilterRuleText(matched),
	}

	// Copy the result to make sure that modifications to the result message
	// down the pipeline don't interfere with the cached value.
	//
	// See AGDNS-359.
	f.resCache.set(host, qt, rm.Clone())
	f.updateCacheSizeMetrics(f.resCache.cache.ItemCount())

	return rm, nil
}

// updateCacheSizeMetrics updates cache size metrics.
func (f *hashPrefixFilter) updateCacheSizeMetrics(size int) {
	switch f.id {
	case agd.FilterListIDSafeBrowsing:
		metrics.HashPrefixFilterSafeBrowsingCacheSize.Set(float64(size))
	case agd.FilterListIDAdultBlocking:
		metrics.HashPrefixFilterAdultBlockingCacheSize.Set(float64(size))
	default:
		panic(fmt.Errorf("unsupported FilterListID %s", f.id))
	}
}

// updateCacheLookupsMetrics updates cache lookups metrics.
func (f *hashPrefixFilter) updateCacheLookupsMetrics(hit bool) {
	var hitsMetric, missesMetric prometheus.Counter
	switch f.id {
	case agd.FilterListIDSafeBrowsing:
		hitsMetric = metrics.HashPrefixFilterCacheSafeBrowsingHits
		missesMetric = metrics.HashPrefixFilterCacheSafeBrowsingMisses
	case agd.FilterListIDAdultBlocking:
		hitsMetric = metrics.HashPrefixFilterCacheAdultBlockingHits
		missesMetric = metrics.HashPrefixFilterCacheAdultBlockingMisses
	default:
		panic(fmt.Errorf("unsupported FilterListID %s", f.id))
	}

	if hit {
		hitsMetric.Inc()
	} else {
		missesMetric.Inc()
	}
}

// name implements the qtHostFilter interface for *hashPrefixFilter.
func (f *hashPrefixFilter) name() (n string) {
	if f == nil {
		return ""
	}

	return string(f.id)
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
