package serviceblock

import (
	"context"
	"fmt"
	"log/slog"
	"path"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdurlflt"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/errors"
)

// indexResp is the struct for the JSON response from a blocked service index
// API.
type indexResp struct {
	BlockedServices []*indexRespService `json:"blocked_services"`
}

// toInternal converts the services from the index to serviceRuleLists.
func (r *indexResp) toInternal(
	ctx context.Context,
	logger *slog.Logger,
	errColl errcoll.Interface,
	cacheManager agdcache.Manager,
	cacheCount int,
	useCache bool,
) (services serviceRuleLists, err error) {
	l := len(r.BlockedServices)
	if l == 0 {
		return nil, nil
	}

	services = make(serviceRuleLists, l)
	errs := make([]error, len(r.BlockedServices))
	for i, svc := range r.BlockedServices {
		var (
			svcID filter.BlockedServiceID
			rl    *rulelist.Immutable
		)

		svcID, rl, err = svc.toInternal(ctx, logger, errColl, cacheManager, cacheCount, useCache)
		if err != nil {
			errs[i] = fmt.Errorf("service at index %d: %w", i, err)

			continue
		}

		services[svcID] = rl
	}

	err = errors.Join(errs...)
	if err != nil {
		return nil, fmt.Errorf("converting blocked services: %w", err)
	}

	return services, nil
}

// indexRespService is the struct for a filter from the JSON response from a
// blocked service index API.
type indexRespService struct {
	ID    string   `json:"id"`
	Rules []string `json:"rules"`
}

// cachePrefix is used as a cache category for filter's caches.
const cachePrefix = "filters"

// toInternal converts the service from the index to a rule-list filter.  It
// also adds the cache with ID "[filter.IDBlockedService]/[svc.ID]" to
// the cache manager.
func (svc *indexRespService) toInternal(
	ctx context.Context,
	logger *slog.Logger,
	errColl errcoll.Interface,
	cacheManager agdcache.Manager,
	cacheCount int,
	useCache bool,
) (svcID filter.BlockedServiceID, rl *rulelist.Immutable, err error) {
	svcID, err = filter.NewBlockedServiceID(svc.ID)
	if err != nil {
		return "", nil, fmt.Errorf("validating id: %w", err)
	}

	if len(svc.Rules) == 0 {
		errColl.Collect(ctx, fmt.Errorf("service filter: no rules for service with id %s", svcID))
		logger.WarnContext(ctx, "service has no rules", "svc_id", svcID)
	}

	fltIDStr := path.Join(cachePrefix, string(filter.IDBlockedService), string(svcID))
	cache := rulelist.NewManagedResultCache(cacheManager, fltIDStr, cacheCount, useCache)
	rulesData := agdurlflt.RulesToBytes(svc.Rules)
	rl = rulelist.NewImmutable(rulesData, filter.IDBlockedService, svcID, cache)

	logger.InfoContext(ctx, "converted service", "svc_id", svcID, "num_rules", rl.RulesCount())

	return svcID, rl, nil
}
