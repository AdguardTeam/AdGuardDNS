// Package serviceblock contains an implementation of a filter that blocks
// services using rule lists.  The blocking is based on the parental-control
// settings in the profile.
package serviceblock

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/log"
)

// Filter is a service-blocking filter that uses rule lists that it gets from an
// index.
type Filter struct {
	// refr is the helper entity containing the refreshable part of the index
	// refresh and caching logic.
	refr *internal.Refreshable

	// mu protects services.
	mu *sync.RWMutex

	// services is an ID to filter mapping.
	services serviceRuleLists

	// errColl used to collect non-critical and rare errors.
	errColl errcoll.Interface
}

// serviceRuleLists is convenient alias for an ID to filter mapping.
type serviceRuleLists = map[agd.BlockedServiceID]*rulelist.Immutable

// New returns a fully initialized service blocker.
func New(refr *internal.Refreshable, errColl errcoll.Interface) (f *Filter) {
	return &Filter{
		refr:     refr,
		mu:       &sync.RWMutex{},
		services: serviceRuleLists{},
		errColl:  errColl,
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
		if rl == nil {
			log.Info("service filter: warning: no service with id %s", id)
		} else {
			rls = append(rls, rl)
		}
	}

	return rls
}

// Refresh loads new service data from the index URL.
func (f *Filter) Refresh(
	ctx context.Context,
	cacheManager agdcache.Manager,
	cacheSize int,
	useCache bool,
	acceptStale bool,
) (err error) {
	fltIDStr := string(agd.FilterListIDBlockedService)
	defer func() {
		if err != nil {
			metrics.FilterUpdatedStatus.WithLabelValues(fltIDStr).Set(0)
		}
	}()

	resp, err := f.loadIndex(ctx, acceptStale)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	services, err := resp.toInternal(ctx, f.errColl, cacheManager, cacheSize, useCache)
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
func (f *Filter) loadIndex(ctx context.Context, acceptStale bool) (resp *indexResp, err error) {
	text, err := f.refr.Refresh(ctx, acceptStale)
	if err != nil {
		return nil, fmt.Errorf("loading index: %w", err)
	}

	resp = &indexResp{}
	err = json.NewDecoder(strings.NewReader(text)).Decode(resp)
	if err != nil {
		return nil, fmt.Errorf("decoding index: %w", err)
	}

	optlog.Debug1("service filter: loaded index with %d blocked services", len(resp.BlockedServices))

	return resp, nil
}
