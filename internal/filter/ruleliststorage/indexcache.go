package ruleliststorage

import (
	"fmt"
	"net/url"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
)

// indexCacheVersion is the current schema version of the rule list index
// cache.
//
// NOTE:  Increment this value on every change in [indexCache] that requires a
// change in the JSON representation.
const indexCacheVersion uint = 1

// indexCache is the data-transfer object for the rule list index cache.
type indexCache struct {
	// Filters contains the data with filters info.
	Filters []*indexFilter `json:"filters"`

	// SchemaVersion is the version of the schema.
	SchemaVersion uint `json:"schema_version"`
}

// indexFilter is a single filter in index.
type indexFilter struct {
	// DownloadURL is the URL to use for downloading this filter.  It's never
	// nil.
	DownloadURL *url.URL `json:"download_url"`

	// UpdateTime is the time when the filter was updated.
	UpdateTime time.Time `json:"upd_time"`

	// FilterID is the identifier of the filter.
	FilterID filter.ID `json:"filter_id"`

	// IsCustom indicates if the filter is a custom filter for a client.
	IsCustom bool `json:"is_custom"`
}

// newIndexCache converts idx into the data-transfer object for filesystem
// caching.  idx must not be nil.
func newIndexCache(idx *filterindex.Rulelist) (c *indexCache) {
	filters := make([]*indexFilter, 0, len(idx.Filters))
	for id, f := range idx.Filters {
		filters = append(filters, &indexFilter{
			DownloadURL: f.DownloadURL,
			UpdateTime:  f.UpdateTime,
			FilterID:    id,
			IsCustom:    f.IsCustom,
		})
	}

	return &indexCache{
		Filters:       filters,
		SchemaVersion: indexCacheVersion,
	}
}

// toInternal converts the index cache from JSON into internal structures.  c
// must be valid.
func (c *indexCache) toInternal() (idx *filterindex.Rulelist, err error) {
	if c.SchemaVersion == 0 {
		// Previous, non-versioned index.  Simply reload from the URL.
		return nil, nil
	}

	err = validate.InRange("schema_version", c.SchemaVersion, indexCacheVersion, indexCacheVersion)
	if err != nil {
		return nil, fmt.Errorf("malformed cache: %w", err)
	}

	var errs []error
	filters := make(map[filter.ID]*filterindex.RulelistFilter, len(c.Filters))
	for i, f := range c.Filters {
		err = f.validate()
		if err != nil {
			errs = append(errs, fmt.Errorf("filter: at index: %d: %w", i, err))

			continue
		}

		filters[f.FilterID] = &filterindex.RulelistFilter{
			DownloadURL: f.DownloadURL,
			UpdateTime:  f.UpdateTime,
			IsCustom:    f.IsCustom,
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return &filterindex.Rulelist{
		Filters: filters,
	}, nil
}

// validate returns an error if f is invalid.
func (f *indexFilter) validate() (err error) {
	if f == nil {
		return errors.ErrNoValue
	}

	errs := []error{
		validate.NotEmpty("filter_id", f.FilterID),
		// TODO(a.garipov):  Use urlutil.URL or add IsValidURLString to golibs.
		validate.NotEmpty("download_url", f.DownloadURL),
		validate.NotEmpty("upd_time", f.UpdateTime),
	}

	return errors.Join(errs...)
}
