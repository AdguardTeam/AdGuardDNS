package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// Filters configuration

// filtersConfig contains the configuration for the filter lists and filtering
// storage to be used.
type filtersConfig struct {
	// CustomFilterCacheSize is the size of the LRU cache of compiled filtering
	// engines for profiles with custom filtering rules.
	CustomFilterCacheSize int `yaml:"custom_filter_cache_size"`

	// SafeSearchCacheSize is the size of the LRU cache of safe-search results.
	SafeSearchCacheSize int `yaml:"safe_search_cache_size"`

	// RuleListCacheSize defines the size of the LRU cache of rule-list
	// filtering results.
	RuleListCacheSize int `yaml:"rule_list_cache_size"`

	// ResponseTTL is the TTL to set for DNS responses to requests for filtered
	// domains.
	ResponseTTL timeutil.Duration `yaml:"response_ttl"`

	// RefreshIvl defines how often AdGuard DNS refreshes the rule-based filters
	// from filter index.
	RefreshIvl timeutil.Duration `yaml:"refresh_interval"`

	// RefreshTimeout is the timeout for the entire filter update operation.
	// Note that each individual refresh operation also has its own hardcoded
	// 30s timeout.
	RefreshTimeout timeutil.Duration `yaml:"refresh_timeout"`

	// UseRuleListCache, if true, enables rule list cache.
	UseRuleListCache bool `yaml:"use_rule_list_cache"`
}

// toInternal converts c to the filter storage configuration for the DNS server.
// cacheDir must exist.  c is assumed to be valid.
func (c *filtersConfig) toInternal(
	errColl agd.ErrorCollector,
	resolver agdnet.Resolver,
	envs *environments,
	safeBrowsing *filter.HashPrefix,
	adultBlocking *filter.HashPrefix,
) (conf *filter.DefaultStorageConfig) {
	return &filter.DefaultStorageConfig{
		FilterIndexURL:            netutil.CloneURL(&envs.FilterIndexURL.URL),
		BlockedServiceIndexURL:    netutil.CloneURL(&envs.BlockedServiceIndexURL.URL),
		GeneralSafeSearchRulesURL: netutil.CloneURL(&envs.GeneralSafeSearchURL.URL),
		YoutubeSafeSearchRulesURL: netutil.CloneURL(&envs.YoutubeSafeSearchURL.URL),
		SafeBrowsing:              safeBrowsing,
		AdultBlocking:             adultBlocking,
		Now:                       time.Now,
		ErrColl:                   errColl,
		Resolver:                  resolver,
		CacheDir:                  envs.FilterCachePath,
		CustomFilterCacheSize:     c.CustomFilterCacheSize,
		SafeSearchCacheSize:       c.SafeSearchCacheSize,
		// TODO(a.garipov): Consider making this configurable.
		SafeSearchCacheTTL: 1 * time.Hour,
		RuleListCacheSize:  c.RuleListCacheSize,
		RefreshIvl:         c.RefreshIvl.Duration,
		UseRuleListCache:   c.UseRuleListCache,
	}
}

// validate returns an error if the filters configuration is invalid.
func (c *filtersConfig) validate() (err error) {
	switch {
	case c == nil:
		return errNilConfig
	case c.SafeSearchCacheSize <= 0:
		return newMustBePositiveError("safe_search_cache_size", c.SafeSearchCacheSize)
	case c.RuleListCacheSize <= 0:
		return newMustBePositiveError("rule_list_cache_size", c.RuleListCacheSize)
	case c.ResponseTTL.Duration <= 0:
		return newMustBePositiveError("response_ttl", c.ResponseTTL)
	case c.RefreshIvl.Duration <= 0:
		return newMustBePositiveError("refresh_interval", c.RefreshIvl)
	case c.RefreshTimeout.Duration <= 0:
		return newMustBePositiveError("refresh_timeout", c.RefreshTimeout)
	default:
		return nil
	}
}

// setupFilterStorage creates and returns a filter storage as well as starts and
// registers its refresher in the signal handler.
func setupFilterStorage(
	conf *filter.DefaultStorageConfig,
	sigHdlr signalHandler,
	errColl agd.ErrorCollector,
	refreshTimeout time.Duration,
) (strg *filter.DefaultStorage, err error) {
	strg, err = filter.NewDefaultStorage(conf)
	if err != nil {
		return nil, fmt.Errorf("creating default filter storage: %w", err)
	}

	refr := agd.NewRefreshWorker(&agd.RefreshWorkerConfig{
		Context: func() (ctx context.Context, cancel context.CancelFunc) {
			return context.WithTimeout(context.Background(), refreshTimeout)
		},
		Refresher:           strg,
		ErrColl:             errColl,
		Name:                "filters",
		Interval:            conf.RefreshIvl,
		RefreshOnShutdown:   false,
		RoutineLogsAreDebug: false,
	})
	err = refr.Start()
	if err != nil {
		return nil, fmt.Errorf("starting default filter storage update: %w", err)
	}

	sigHdlr.add(refr)

	return strg, nil
}
