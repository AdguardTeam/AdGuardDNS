package filter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/prometheus/client_golang/prometheus"
)

// Service Blocking Filter

// serviceBlocker is a filter that blocks services based on the settings in
// profile.
//
// TODO(a.garipov): Add tests.
type serviceBlocker struct {
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
type serviceRuleLists = map[agd.BlockedServiceID]*ruleListFilter

// newServiceBlocker returns a fully initialized service blocker.
func newServiceBlocker(indexURL *url.URL, errColl agd.ErrorCollector) (b *serviceBlocker) {
	return &serviceBlocker{
		url: indexURL,
		http: agdhttp.NewClient(&agdhttp.ClientConfig{
			Timeout: defaultFilterRefreshTimeout,
		}),
		mu:      &sync.RWMutex{},
		errColl: errColl,
	}
}

// ruleLists returns the rule list filters for the given blocked service IDs.
// The order of the elements in rls is undefined.
func (b *serviceBlocker) ruleLists(ids []agd.BlockedServiceID) (rls []*ruleListFilter) {
	if len(ids) == 0 {
		return nil
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, id := range ids {
		rl := b.services[id]
		if rl == nil {
			log.Info("service filter: no service with id %q", id)

			continue
		}

		rls = append(rls, rl)
	}

	return rls
}

// refresh loads new service data from the index URL.
func (b *serviceBlocker) refresh(
	ctx context.Context,
	cacheSize int,
	useCache bool,
) (err error) {
	// Report the services update to prometheus.
	promLabels := prometheus.Labels{
		"filter": string(agd.FilterListIDBlockedService),
	}

	defer func() {
		if err != nil {
			agd.Collectf(ctx, b.errColl, "refreshing blocked services: %w", err)
			metrics.FilterUpdatedStatus.With(promLabels).Set(0)
		}
	}()

	resp, err := b.loadIndex(ctx)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	services, err := resp.toInternal(cacheSize, useCache)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.services = services

	count := 0
	for _, s := range services {
		count += s.engine.RulesCount
	}
	metrics.FilterRulesTotal.With(promLabels).Set(float64(count))
	metrics.FilterUpdatedTime.With(promLabels).SetToCurrentTime()
	metrics.FilterUpdatedStatus.With(promLabels).Set(1)

	return nil
}

// loadIndex fetches, decodes, and returns the blocked service index data.
func (b *serviceBlocker) loadIndex(ctx context.Context) (resp *svcIndexResp, err error) {
	defer func() { err = errors.Annotate(err, "loading blocked service index from %q: %w", b.url) }()

	httpResp, err := b.http.Get(ctx, b.url)
	if err != nil {
		return nil, fmt.Errorf("requesting: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, httpResp.Body.Close()) }()

	err = agdhttp.CheckStatus(httpResp, http.StatusOK)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	resp = &svcIndexResp{}
	err = json.NewDecoder(httpResp.Body).Decode(resp)
	if err != nil {
		return nil, agdhttp.WrapServerError(
			fmt.Errorf("decoding: %w", err),
			httpResp,
		)
	}

	log.Debug("service filter: loaded index with %d blocked services", len(resp.BlockedServices))

	return resp, nil
}

// svcIndexResp is the struct for the JSON response from a blocked service index
// API.
type svcIndexResp struct {
	BlockedServices []*svcIndexRespService `json:"blocked_services"`
}

// toInternal converts the services from the index to serviceRuleLists.
func (r *svcIndexResp) toInternal(
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
		var id agd.BlockedServiceID
		id, err = agd.NewBlockedServiceID(svc.ID)
		if err != nil {
			errs[i] = fmt.Errorf("service at index %d: validating id: %w", i, err)

			continue
		}

		if len(svc.Rules) == 0 {
			log.Info("service filter: no rules for service with id %s", id)

			continue
		}

		text := strings.Join(svc.Rules, "\n")

		var rl *ruleListFilter
		rl, err = newRuleListFltFromStr(
			text,
			agd.FilterListIDBlockedService,
			svc.ID,
			cacheSize,
			useCache,
		)
		if err != nil {
			errs[i] = fmt.Errorf("compiling %s: %w", svc.ID, err)

			continue
		}

		services[id] = rl
	}

	err = errors.Join(errs...)
	if err != nil {
		return nil, fmt.Errorf("converting blocked services: %w", err)
	}

	return services, nil
}

// svcIndexRespService is the struct for a filter from the JSON response from
// a blocked service index API.
type svcIndexRespService struct {
	ID    string   `json:"id"`
	Rules []string `json:"rules"`
}
