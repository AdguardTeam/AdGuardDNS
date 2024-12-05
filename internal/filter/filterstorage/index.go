package filterstorage

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/errors"
)

// indexResp is the struct for the JSON response from a filter index API.
//
// TODO(a.garipov):  Consider exporting for tests?
type indexResp struct {
	Filters []*indexRespFilter `json:"filters"`
}

// indexRespFilter is the struct for a filter from the JSON response from a
// filter index API.
//
// NOTE:  Keep these strings instead of unmarshalers to make sure that objects
// with invalid data do not prevent valid objects from being used.
type indexRespFilter struct {
	// DownloadURL contains the URL to use for downloading this filter.
	DownloadURL string `json:"downloadUrl"`

	// Key contains the ID of the filter as a string.
	Key string `json:"filterKey"`
}

// compare is the comparison function for filters in the index.  f and other may
// be nil; nil filters are sorted after non-nil ones.
func (f *indexRespFilter) compare(other *indexRespFilter) (res int) {
	if f == nil {
		if other == nil {
			return 0
		}

		return 1
	} else if other == nil {
		return -1
	}

	return cmp.Compare(f.Key, other.Key)
}

// validate returns an error if f is invalid.
func (f *indexRespFilter) validate() (err error) {
	if f == nil {
		return errors.ErrNoValue
	}

	var errs []error

	// TODO(a.garipov):  Use urlutil.URL or add IsValidURLString to golibs.
	if f.DownloadURL == "" {
		errs = append(errs, fmt.Errorf("downloadUrl: %w", errors.ErrEmptyValue))
	}

	if _, err = filter.NewID(f.Key); err != nil {
		errs = append(errs, fmt.Errorf("filterKey: %w", err))
	}

	return errors.Join(errs...)
}

// indexData is the data of a single item in the filtering-rule index response.
type indexData struct {
	url *url.URL
	id  filter.ID
}

// toInternal converts the filters from the index to []*indexData.  All errors
// are logged and collected.  logger and errColl must not be nil.
func (r *indexResp) toInternal(
	ctx context.Context,
	logger *slog.Logger,
	errColl errcoll.Interface,
) (fls []*indexData) {
	fls = make([]*indexData, 0, len(r.Filters))
	for i, rf := range r.Filters {
		err := rf.validate()
		if err != nil {
			err = fmt.Errorf("validating filter at index %d: %w", i, err)
			errcoll.Collect(ctx, errColl, logger, "index response", err)

			continue
		}

		u, err := agdhttp.ParseHTTPURL(rf.DownloadURL)
		if err != nil {
			err = fmt.Errorf("validating url: %w", err)
			errcoll.Collect(ctx, errColl, logger, "index response", err)

			continue
		}

		fls = append(fls, &indexData{
			url: u,
			// Use a simple conversion, since [*indexRespFilter.validate] has
			// already made sure that the ID is valid.
			id: filter.ID(rf.Key),
		})
	}

	return fls
}
