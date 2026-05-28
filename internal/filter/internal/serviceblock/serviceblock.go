// Package serviceblock contains an implementation of a filter that blocks
// services using rule lists.  The blocking is based on the parental-control
// settings in the profile.
package serviceblock

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/timeutil"
)

// Filter is a service-blocking filter that uses rule lists that it gets from an
// index.
type Filter struct {
	logger *slog.Logger
	clock  timeutil.Clock
	refr   *refreshable.Refreshable

	// mu protects services.
	mu       *sync.RWMutex
	services serviceRuleLists

	errColl errcoll.Interface
	metrics filter.Metrics
}

// serviceRuleLists is convenient alias for an ID to filter mapping.
type serviceRuleLists = map[filter.BlockedServiceID]*rulelist.Immutable

// Config is the configuration for the service-blocking filter.
type Config struct {
	// Refreshable is the configuration of the refreshable index of the
	// service-blocking filter.  It must not be nil and must be valid.
	Refreshable *refreshable.Config

	// Clock is used to get the current time.  It must not be nil.
	Clock timeutil.Clock

	// ErrColl used to collect non-critical and rare errors.  It must not be
	// nil.
	ErrColl errcoll.Interface

	// Metrics are the metrics for the service-blocking filter.  It must not be
	// nil.
	Metrics filter.Metrics
}

// New returns a fully initialized service blocker.  c must not be nil and must
// be valid.
func New(c *Config) (f *Filter, err error) {
	refr, err := refreshable.New(c.Refreshable)
	if err != nil {
		return nil, fmt.Errorf("creating refreshable for service index: %w", err)
	}

	return &Filter{
		logger:   c.Refreshable.Logger,
		clock:    c.Clock,
		refr:     refr,
		mu:       &sync.RWMutex{},
		services: serviceRuleLists{},
		errColl:  c.ErrColl,
		metrics:  c.Metrics,
	}, nil
}

// AppendRuleLists appends the rule-list filters for the given blocked service
// IDs to the given slice.  The order of the appended elements is undefined.
func (f *Filter) AppendRuleLists(
	ctx context.Context,
	orig []*rulelist.Immutable,
	ids []filter.BlockedServiceID,
) (res []*rulelist.Immutable) {
	res = orig
	if len(ids) == 0 {
		return res
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	for _, id := range ids {
		rl := f.services[id]
		if rl == nil {
			f.logger.WarnContext(ctx, "no service with id", "id", id)
		} else {
			res = append(res, rl)
		}
	}

	return res
}

// Refresh loads new service data from the index URL.
func (f *Filter) Refresh(
	ctx context.Context,
	cacheManager agdcache.Manager,
	cacheCount uint64,
	useCache bool,
	acceptStale bool,
) (err error) {
	var (
		count     uint64
		sizeBytes uint64
	)
	defer func() {
		// TODO(a.garipov):  Consider using [agdtime.Clock].
		f.metrics.SetStatus(ctx, &filter.StatusUpdate{
			Error:      err,
			UpdateTime: f.clock.Now(),
			ID:         string(filter.IDBlockedService),
			RuleCount:  count,
			SizeBytes:  sizeBytes,
		})
	}()

	resp, sizeBytes, err := f.loadIndex(ctx, acceptStale)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	services, err := resp.toInternal(ctx, f.logger, f.errColl, cacheManager, cacheCount, useCache)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	for _, s := range services {
		count += s.RulesCount()
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.services = services

	return nil
}

// loadIndex fetches, decodes, and returns the blocked service index data.
// sizeBytes is the size of the marshaled filter index data.
func (f *Filter) loadIndex(
	ctx context.Context,
	acceptStale bool,
) (resp *indexResp, sizeBytes uint64, err error) {
	b, err := f.refr.Refresh(ctx, acceptStale)
	if err != nil {
		return nil, 0, fmt.Errorf("loading index: %w", err)
	}

	resp = &indexResp{}
	err = json.Unmarshal(b, resp)
	if err != nil {
		return nil, 0, fmt.Errorf("decoding index: %w", err)
	}

	f.logger.DebugContext(ctx, "loaded index", "num_svc", len(resp.BlockedServices))

	return resp, uint64(len(b)), nil
}
