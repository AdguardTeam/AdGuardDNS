// Package filterstorage defines an interface for a storage of filters as well
// as the default implementation and the filter configuration.
package filterstorage

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
)

// Additional synthetic filter IDs for refreshable indexes.
//
// TODO(a.garipov):  Consider using a separate type.
const (
	FilterIDBlockedServiceIndex   filter.ID = "blocked_service_index"
	FilterIDRuleListIndex         filter.ID = "rule_list_index"
	FilterIDStandardProfileAccess filter.ID = "standard_profile_access"
)

// Filenames for filter indexes.
const (
	indexFileNameBlockedServices       = "services.json"
	indexFileNameRuleLists             = "filters.json"
	indexFileNameStandardProfileAccess = "standard_profile_access.json"
)

// Constants that define cache identifiers for the cache manager.
const (
	// cachePrefixSafeSearch is used as a cache prefix for safe-search filters.
	cachePrefixSafeSearch = "filters/safe_search"

	// cachePrefixRuleList is used a cache prefix for rule-list filters.
	cachePrefixRuleList = "filters/rulelist"
)
