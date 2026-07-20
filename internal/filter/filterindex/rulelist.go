package filterindex

import (
	"context"
	"net/url"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
)

// RulelistStorage is the temporary interface for storages of rule list filters
// indexes.
//
// TODO(d.kolyshev):  Merge this interface to [Storage] after the rule list
// filters index is added in backend gRPC.
type RulelistStorage interface {
	// Rulelist returns the current rule list filters index.
	Rulelist(ctx context.Context) (idx *Rulelist, err error)
}

// EmptyRulelistStorage is the [RulelistStorage] implementation that does
// nothing.
type EmptyRulelistStorage struct{}

// type check
var _ RulelistStorage = EmptyRulelistStorage{}

// Rulelist implements the [RulelistStorage] interface for EmptyRulelistStorage.
// idx and err are always nil.
func (EmptyRulelistStorage) Rulelist(_ context.Context) (idx *Rulelist, err error) {
	return nil, nil
}

// Rulelist is a rule list filters index.
type Rulelist struct {
	// Filters is a map of filter identifiers to index data.
	Filters map[filter.ID]*RulelistFilter
}

// RulelistFilter is a struct for the rule list filter got from filter index
// API.
type RulelistFilter struct {
	// DownloadURL is the URL to use for downloading this filter.  It must not
	// be nil.
	DownloadURL *url.URL

	// UpdateTime is the time when the filter was updated.
	UpdateTime time.Time

	// IsCustom indicates if the filter is a custom filter for a client.
	//
	// TODO(d.kolyshev):  Use.
	IsCustom bool
}
