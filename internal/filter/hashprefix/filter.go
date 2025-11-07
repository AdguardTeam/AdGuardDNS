package hashprefix

import (
	"context"
	"fmt"
	"log/slog"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"path"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/c2h5oh/datasize"
	"github.com/miekg/dns"
)

// FilterConfig is the hash-prefix filter configuration structure.
type FilterConfig struct {
	// Logger is used for logging the operation of the filter.
	Logger *slog.Logger

	// Cloner is used to clone messages taken from filtering-result cache.
	Cloner *dnsmsg.Cloner

	// CacheManager is the global cache manager.  CacheManager must not be nil.
	CacheManager agdcache.Manager

	// Hashes are the hostname hashes for this filter.
	Hashes *Storage

	// URL is the URL used to update the filter.
	URL *url.URL

	// ErrColl is used to collect non-critical and rare errors.
	ErrColl errcoll.Interface

	// HashPrefixMetrics are the specific metrics for the hashprefix filter.
	HashPrefixMetrics Metrics

	// Metrics are the metrics for the hashprefix filter.
	Metrics filter.Metrics

	// PublicSuffixList is used for obtaining public suffix for specified
	// domain.
	PublicSuffixList cookiejar.PublicSuffixList

	// ID is the ID of this hash storage for logging and error reporting.
	ID filter.ID

	// CachePath is the path to the file containing the cached filtered
	// hostnames, one per line.
	CachePath string

	// ReplacementHost is the replacement host for this filter.  Queries matched
	// by the filter receive a response with the IP addresses of this host.  If
	// ReplacementHost contains a valid IP, that IP is used.  Otherwise, it
	// should be a valid domain name.
	ReplacementHost string

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

	// SubDomainNum defines how many labels should be hashed to match against a
	// hash prefix filter.  It must be positive and fit into int.
	SubDomainNum uint
}

// Filter is a filter that matches hosts by their hashes based on a hash-prefix
// table.  It should be initially refreshed with [Filter.RefreshInitial].
type Filter struct {
	logger           *slog.Logger
	cloner           *dnsmsg.Cloner
	hashes           *Storage
	refr             *refreshable.Refreshable
	subDomainsPool   *syncutil.Pool[[]string]
	errColl          errcoll.Interface
	hashprefixMtrc   Metrics
	publicSuffixList cookiejar.PublicSuffixList
	metrics          filter.Metrics
	resCache         agdcache.Interface[rulelist.CacheKey, filter.Result]
	id               filter.ID
	repIP            netip.Addr
	repFQDN          string
	subDomainNum     int
}

// IDPrefix is a common prefix for cache IDs, logging, and refreshes of
// hashprefix filters.
//
// TODO(a.garipov):  Consider better names.
const IDPrefix = "filters/hashprefix"

// NewFilter returns a new hash-prefix filter.  It also adds the caches with IDs
// [FilterListIDAdultBlocking], [FilterListIDSafeBrowsing], and
// [FilterListIDNewRegDomains] to the cache manager.  c must not be nil.
func NewFilter(c *FilterConfig) (f *Filter, err error) {
	id := c.ID

	resCache := agdcache.NewLRU[rulelist.CacheKey, filter.Result](&agdcache.LRUConfig{
		Count: c.CacheCount,
	})

	c.CacheManager.Add(path.Join(IDPrefix, string(id)), resCache)

	f = &Filter{
		logger: c.Logger,
		cloner: c.Cloner,
		hashes: c.Hashes,
		// #nosec G115 -- Assume that c.SubDomainNum is always less then or
		// equal to 63.
		//
		// TODO(f.setrakov): Validate c.SubDomainsNum.
		subDomainsPool:   syncutil.NewSlicePool[string](int(c.SubDomainNum)),
		errColl:          c.ErrColl,
		hashprefixMtrc:   c.HashPrefixMetrics,
		publicSuffixList: c.PublicSuffixList,
		metrics:          c.Metrics,
		resCache:         resCache,
		id:               id,
		// #nosec G115 -- The value is a constant less than int accommodates.
		subDomainNum: int(c.SubDomainNum),
	}

	repHost := c.ReplacementHost
	ip, err := netip.ParseAddr(repHost)
	if err != nil {
		err = netutil.ValidateDomainName(repHost)
		if err != nil {
			return nil, fmt.Errorf("replacement host: %w", err)
		}

		f.repFQDN = dns.Fqdn(repHost)
	} else {
		f.repIP = ip
	}

	f.refr, err = refreshable.New(&refreshable.Config{
		Logger:    f.logger,
		URL:       c.URL,
		ID:        id,
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
// It modifies the request or response if host matches f.
func (f *Filter) FilterRequest(
	ctx context.Context,
	req *filter.Request,
) (r filter.Result, err error) {
	host, qt, cl := req.Host, req.QType, req.QClass

	cacheKey := rulelist.NewCacheKey(host, qt, cl, false)
	item, ok := f.resCache.Get(cacheKey)
	f.hashprefixMtrc.IncrementLookups(ctx, ok)
	if ok {
		return f.clonedResult(req.DNS, item), nil
	}

	fam, ok := isFilterable(qt)
	if !ok {
		return nil, nil
	}

	var matched string
	subPtr := f.subDomainsPool.Get()
	defer f.subDomainsPool.Put(subPtr)

	*subPtr = agdnet.AppendSubdomains((*subPtr)[:0], host, f.subDomainNum, f.publicSuffixList)
	for _, s := range *subPtr {
		if f.hashes.Matches(s) {
			matched = s

			break
		}
	}

	if matched == "" {
		f.resCache.Set(cacheKey, nil)

		return nil, nil
	}

	r, err = f.filteredResult(req, matched, fam)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	f.setInCache(cacheKey, r)

	f.hashprefixMtrc.UpdateCacheSize(ctx, f.resCache.Len())

	return r, nil
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

// clonedResult returns a clone of the result based on its type.  r must be nil,
// [*filter.ResultModifiedRequest], or [*filter.ResultModifiedResponse].
func (f *Filter) clonedResult(req *dns.Msg, r filter.Result) (clone filter.Result) {
	switch r := r.(type) {
	case nil:
		return nil
	case *filter.ResultModifiedRequest:
		return r.Clone(f.cloner)
	case *filter.ResultModifiedResponse:
		return r.CloneForReq(f.cloner, req)
	default:
		panic(fmt.Errorf("hashprefix: unexpected type for result: %T(%[1]v)", r))
	}
}

// filteredResult returns a filtered request or response.  req must not be nil.
func (f *Filter) filteredResult(
	req *filter.Request,
	matched string,
	fam netutil.AddrFamily,
) (r filter.Result, err error) {
	if f.repFQDN != "" {
		// Assume that the repFQDN is a valid domain name then.
		modReq := f.cloner.Clone(req.DNS)
		modReq.Question[0].Name = dns.Fqdn(f.repFQDN)

		return &filter.ResultModifiedRequest{
			Msg:  modReq,
			List: f.id,
			Rule: filter.RuleText(matched),
		}, nil
	}

	resp, err := f.respForFamily(req, fam)
	if err != nil {
		return nil, fmt.Errorf("filter %s: creating modified result: %w", f.id, err)
	}

	return &filter.ResultModifiedResponse{
		Msg:  resp,
		List: f.id,
		Rule: filter.RuleText(matched),
	}, nil
}

// respForFamily returns a filtered response in accordance with the protocol
// family and question type.
func (f *Filter) respForFamily(
	req *filter.Request,
	fam netutil.AddrFamily,
) (resp *dns.Msg, err error) {
	if fam == netutil.AddrFamilyNone {
		// This is an HTTPS query.  For them, just return NODATA or other
		// blocked response.  See AGDNS-1551.
		//
		// TODO(ameshkov): Consider putting the resolved IP addresses into hints
		// to show the blocked page here as well?
		return req.Messages.NewBlockedResp(req.DNS, nil)
	}

	ip := f.repIP

	switch {
	case ip.Is4() && fam == netutil.AddrFamilyIPv4:
		return req.Messages.NewBlockedRespIP(req.DNS, ip)
	case ip.Is6() && fam == netutil.AddrFamilyIPv6:
		return req.Messages.NewBlockedRespIP(req.DNS, ip)
	default:
		// TODO(e.burkov):  Use [dnsmsg.Constructor.NewBlockedRespRCode] when it
		// adds SOA records.
		resp = req.Messages.NewRespRCode(req.DNS, dns.RcodeSuccess)
		req.Messages.AddEDE(req.DNS, resp, dns.ExtendedErrorCodeFiltered)

		return resp, nil
	}
}

// setInCache sets r in cache.  It clones the result to make sure that
// modifications to the result message down the pipeline don't interfere with
// the cached value.  r must be either [*filter.ResultModifiedRequest] or
// [*filter.ResultModifiedResponse].
//
// See AGDNS-359.
func (f *Filter) setInCache(k rulelist.CacheKey, r filter.Result) {
	switch r := r.(type) {
	case *filter.ResultModifiedRequest:
		f.resCache.Set(k, r.Clone(f.cloner))
	case *filter.ResultModifiedResponse:
		f.resCache.Set(k, r.Clone(f.cloner))
	default:
		panic(fmt.Errorf("hashprefix: unexpected type for result: %T(%[1]v)", r))
	}
}

// type check
var _ service.Refresher = (*Filter)(nil)

// Refresh implements the [service.Refresher] interface for *Filter.
func (f *Filter) Refresh(ctx context.Context) (err error) {
	f.logger.InfoContext(ctx, "refresh started")
	defer f.logger.InfoContext(ctx, "refresh finished")

	err = f.refresh(ctx, false)
	if err != nil {
		errcoll.Collect(ctx, f.errColl, f.logger, fmt.Sprintf("refreshing %q", f.id), err)
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
		return fmt.Errorf("refreshing hashprefix filter initially: %w", err)
	}

	return nil
}

// refresh reloads and resets the hash-filter data.  If acceptStale is true, do
// not try to load the list from its URL when there is already a file in the
// cache directory, regardless of its staleness.
func (f *Filter) refresh(ctx context.Context, acceptStale bool) (err error) {
	var count int
	defer func() {
		// TODO(a.garipov):  Consider using [agdtime.Clock].
		f.metrics.SetFilterStatus(ctx, string(f.id), time.Now(), count, err)
	}()

	b, err := f.refr.Refresh(ctx, acceptStale)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	count, err = f.hashes.Reset(b)
	if err != nil {
		return fmt.Errorf("%s: resetting: %w", f.id, err)
	}

	f.resCache.Clear()

	f.logger.InfoContext(ctx, "reset hosts", "num", count)

	return nil
}
