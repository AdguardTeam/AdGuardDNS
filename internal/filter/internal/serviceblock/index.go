package serviceblock

import (
	"context"
	"fmt"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
)

// indexResp is the struct for the JSON response from a blocked service index
// API.
type indexResp struct {
	BlockedServices []*indexRespService `json:"blocked_services"`
}

// toInternal converts the services from the index to serviceRuleLists.
func (r *indexResp) toInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	cacheManager agdcache.Manager,
	cacheSize int,
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
			svcID agd.BlockedServiceID
			rl    *rulelist.Immutable
		)

		svcID, rl, err = svc.toInternal(ctx, errColl, cacheManager, cacheSize, useCache)
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

// toInternal converts the service from the index to a rule-list filter.  It
// also adds the cache with ID "[agd.FilterListIDBlockedService]/[svc.ID]" to
// the cache manager.
func (svc *indexRespService) toInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	cacheManager agdcache.Manager,
	cacheSize int,
	useCache bool,
) (svcID agd.BlockedServiceID, rl *rulelist.Immutable, err error) {
	svcID, err = agd.NewBlockedServiceID(svc.ID)
	if err != nil {
		return "", nil, fmt.Errorf("validating id: %w", err)
	}

	if len(svc.Rules) == 0 {
		reportErr := fmt.Errorf("service filter: no rules for service with id %s", svcID)
		errColl.Collect(ctx, reportErr)
		log.Info("warning: %s", reportErr)
	}

	fltIDStr := string(agd.FilterListIDBlockedService) + "/" + string(svcID)
	cache := rulelist.NewManagedResultCache(
		cacheManager,
		fltIDStr,
		cacheSize,
		useCache,
	)
	rl, err = rulelist.NewImmutable(
		strings.Join(svc.Rules, "\n"),
		agd.FilterListIDBlockedService,
		svcID,
		cache,
	)
	if err != nil {
		return "", nil, fmt.Errorf("compiling %s: %w", svc.ID, err)
	}

	log.Info("%s: got %d rules", fltIDStr, rl.RulesCount())

	return svcID, rl, nil
}
