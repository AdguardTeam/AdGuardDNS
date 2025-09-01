// Package safesearch contains the implementation of the safe-search filter
// that uses lists of DNS rewrite rules to enforce safe search.
package safesearch

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/composite"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/urlfilter"
	"github.com/miekg/dns"
)

// Filter modifies the results of queries to search-engine addresses and
// rewrites them to the IP addresses of their safe versions.
type Filter struct {
	flt *rulelist.Refreshable
}

// Config contains configuration for the safe-search filter.
type Config struct {
	// Refreshable is the configuration of the refreshable filter-list within
	// the safe-search filter.
	Refreshable *refreshable.Config

	// CacheTTL is the time to live of the result cache-items.
	//
	//lint:ignore U1000 TODO(a.garipov): Currently unused.  See AGDNS-398.
	CacheTTL time.Duration
}

// New returns a new safe-search filter.  c must not be nil.  The initial
// refresh should be called explicitly if necessary.
func New(c *Config, cache rulelist.ResultCache) (f *Filter, err error) {
	f = &Filter{}

	f.flt, err = rulelist.NewRefreshable(c.Refreshable, cache)
	if err != nil {
		return nil, fmt.Errorf("creating rulelist: %w", err)
	}

	return f, nil
}

// type check
var _ composite.RequestFilterUF = (*Filter)(nil)

// FilterRequestUF implements the [composite.RequestFilterUF] interface for
// *Filter.  It modifies the response if host matches f.
func (f *Filter) FilterRequestUF(
	ctx context.Context,
	req *filter.Request,
	ufReq *urlfilter.DNSRequest,
	ufRes *urlfilter.DNSResult,
) (r filter.Result, err error) {
	qt := req.QType
	switch qt {
	case dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS:
		// Go on.
	default:
		return nil, nil
	}

	ufReq.Hostname = req.Host
	ufReq.DNSType = req.QType

	ok := f.flt.SetURLFilterResult(ctx, ufReq, ufRes)
	if !ok {
		return nil, nil
	}

	id, _ := f.flt.ID()

	r = rulelist.ProcessDNSRewrites(req, ufRes.DNSRewrites(), id)

	replaceRule(r, req.Host)

	return r, nil
}

// replaceRule replaces the r.Rule with host if r is not nil.  r must be nil,
// [*filter.ResultModifiedRequest], or [*filter.ResultModifiedResponse].
func replaceRule(r filter.Result, host string) {
	rule := filter.RuleText(host)
	switch r := r.(type) {
	case nil:
		// Do nothing.
	case *filter.ResultModifiedRequest:
		r.Rule = rule
	case *filter.ResultModifiedResponse:
		r.Rule = rule
	default:
		panic(fmt.Errorf("safesearch: unexpected type for result: %T(%[1]v)", r))
	}
}

// Refresh reloads the rule list data.  If acceptStale is true, and the cache
// file exists, the data is read from there regardless of its staleness.
func (f *Filter) Refresh(ctx context.Context, acceptStale bool) (err error) {
	return f.flt.Refresh(ctx, acceptStale)
}
