package cmd

import (
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// Filters Configuration

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
	envs *environments,
) (conf *filter.DefaultStorageConfig) {
	return &filter.DefaultStorageConfig{
		FilterIndexURL:            netutil.CloneURL(&envs.FilterIndexURL.URL),
		BlockedServiceIndexURL:    netutil.CloneURL(&envs.BlockedServiceIndexURL.URL),
		GeneralSafeSearchRulesURL: netutil.CloneURL(&envs.GeneralSafeSearchURL.URL),
		YoutubeSafeSearchRulesURL: netutil.CloneURL(&envs.YoutubeSafeSearchURL.URL),
		Now:                       time.Now,
		ErrColl:                   errColl,
		Resolver:                  agdnet.DefaultResolver{},
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
