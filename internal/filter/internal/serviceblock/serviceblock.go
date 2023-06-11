// Package serviceblock contains an implementation of a filter that blocks
// services using rule lists.  The blocking is based on the parental-control
// settings in the profile.
package serviceblock

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
)

// Filter is a service-blocking filter that uses rule lists that it gets from an
// index.
type Filter struct {
	// url is the URL from which the services are fetched.
	url *url.URL

	// http is the HTTP client used to refresh the filter.
	http *agdhttp.Client

	// mu protects services.
	mu *sync.RWMutex

	// services is an ID to filter mapping.
	services serviceRuleLists

	// errColl used to collect non-critical and rare errors.
	errColl agd.ErrorCollector
}

// serviceRuleLists is convenient alias for a ID to filter mapping.
type serviceRuleLists = map[agd.BlockedServiceID]*rulelist.Immutable

// New returns a fully initialized service blocker.
func New(indexURL *url.URL, errColl agd.ErrorCollector) (f *Filter) {
	return &Filter{
		url: indexURL,
		http: agdhttp.NewClient(&agdhttp.ClientConfig{
			Timeout: internal.DefaultFilterRefreshTimeout,
		}),
		mu:      &sync.RWMutex{},
		errColl: errColl,
	}
}

// RuleLists returns the rule-list filters for the given blocked service IDs.
// The order of the elements in rls is undefined.
func (f *Filter) RuleLists(
	ctx context.Context,
	ids []agd.BlockedServiceID,
) (rls []*rulelist.Immutable) {
	if len(ids) == 0 {
		return nil
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	for _, id := range ids {
		rl := f.services[id]
		if rl != nil {
			rls = append(rls, rl)

			continue
		}

		reportErr := fmt.Errorf("service filter: no service with id %s", id)
		f.errColl.Collect(ctx, reportErr)
		log.Info("warning: %s", reportErr)
	}

	return rls
}

// Refresh loads new service data from the index URL.
func (f *Filter) Refresh(ctx context.Context, cacheSize int, useCache bool) (err error) {
	fltIDStr := string(agd.FilterListIDBlockedService)
	defer func() {
		if err != nil {
			metrics.FilterUpdatedStatus.WithLabelValues(fltIDStr).Set(0)
		}
	}()

	resp, err := f.loadIndex(ctx)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	services, err := resp.toInternal(ctx, f.errColl, cacheSize, useCache)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	count := 0
	for _, s := range services {
		count += s.RulesCount()
	}

	metrics.FilterRulesTotal.WithLabelValues(fltIDStr).Set(float64(count))
	metrics.FilterUpdatedTime.WithLabelValues(fltIDStr).SetToCurrentTime()
	metrics.FilterUpdatedStatus.WithLabelValues(fltIDStr).Set(1)

	f.mu.Lock()
	defer f.mu.Unlock()

	f.services = services

	return nil
}

// loadIndex fetches, decodes, and returns the blocked service index data.
func (f *Filter) loadIndex(ctx context.Context) (resp *indexResp, err error) {
	defer func() { err = errors.Annotate(err, "loading blocked service index from %q: %w", f.url) }()

	httpResp, err := f.http.Get(ctx, f.url)
	if err != nil {
		return nil, fmt.Errorf("requesting: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, httpResp.Body.Close()) }()

	err = agdhttp.CheckStatus(httpResp, http.StatusOK)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	resp = &indexResp{}
	err = json.NewDecoder(httpResp.Body).Decode(resp)
	if err != nil {
		return nil, agdhttp.WrapServerError(fmt.Errorf("decoding: %w", err), httpResp)
	}

	log.Debug("service filter: loaded index with %d blocked services", len(resp.BlockedServices))

	return resp, nil
}
