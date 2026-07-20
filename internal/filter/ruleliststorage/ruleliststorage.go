// Package ruleliststorage defines an interface for a storage of rule lists as
// well as the default implementation.
package ruleliststorage

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/service"
)

// indexFileNameRuleLists is the name of the rule list index file.
const indexFileNameRuleLists = "filters.json"

// cachePrefixRuleList is used a cache prefix for rule-list filters.
const cachePrefixRuleList = "filters/rulelist"

// StoragePrefix is a common prefix for logging.
//
// TODO(a.garipov): Consider extracting these kinds of IDs to agdcache or some
// other package.
const StoragePrefix = "filters/ruleliststorage"

// Storage is the interface for rule list storages.
type Storage interface {
	service.Refresher

	// AppendForListIDs appends rule lists for the given identifiers to orig.
	AppendForListIDs(
		ctx context.Context,
		orig []*rulelist.Refreshable,
		ids []filter.ID,
	) (rls []*rulelist.Refreshable)

	// HasListID returns true if id is known to the storage.
	HasListID(ctx context.Context, id filter.ID) (ok bool)
}
