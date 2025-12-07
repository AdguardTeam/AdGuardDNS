package filterstorage

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
)

// categoryResp is the struct for the JSON response from a category filter index
// API.
//
// TODO(a.garipov):  Consider exporting for tests?
type categoryResp struct {
	Filters map[string]*categoryRespFilter `json:"filters"`
}

// categoryRespFilter is the struct for a filter from the JSON response from a
// category filter index API.
//
// NOTE:  Keep these strings instead of unmarshalers to make sure that objects
// with invalid data do not prevent valid objects from being used.
type categoryRespFilter struct {
	// DownloadURL contains the URL to use for downloading this filter.
	DownloadURL string `json:"downloadUrl"`
}

// validate returns an error if f is invalid.
func (f *categoryRespFilter) validate(categoryName string) (err error) {
	if f == nil {
		return errors.ErrNoValue
	}

	var errs []error

	// TODO(a.garipov):  Use urlutil.URL or add IsValidURLString to golibs.
	if f.DownloadURL == "" {
		errs = append(errs, fmt.Errorf("downloadUrl: %w", errors.ErrEmptyValue))
	}

	if _, err = filter.NewCategoryID(categoryName); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// categoryData is the data of a single item in the category filtering-rule
// index response.
type categoryData struct {
	url *url.URL
	id  filter.CategoryID
}

// toInternal converts the filters from the index to []*categoryData.  All
// errors are logged and collected.  logger and errColl must not be nil.
func (r *categoryResp) toInternal(
	ctx context.Context,
	logger *slog.Logger,
	errColl errcoll.Interface,
) (fls []*categoryData) {
	ids := container.NewMapSet[filter.CategoryID]()

	fls = make([]*categoryData, 0, len(r.Filters))
	for cat, fl := range r.Filters {
		err := fl.validate(cat)
		if err != nil {
			err = fmt.Errorf("validating category filter %q: %w", cat, err)
			errcoll.Collect(ctx, errColl, logger, "category index response", err)

			continue
		}

		u, err := agdhttp.ParseHTTPURL(fl.DownloadURL)
		if err != nil {
			err = fmt.Errorf("validating url: %w", err)
			errcoll.Collect(ctx, errColl, logger, "category index response", err)

			continue
		}

		// Use a simple conversion, since [*categoryRespFilter.validate] has
		// already made sure that the ID is valid.
		id := filter.CategoryID(cat)
		if ids.Has(id) {
			err = fmt.Errorf("category id: %w: %q", errors.ErrDuplicated, cat)
			errcoll.Collect(ctx, errColl, logger, "category index response", err)

			continue
		}

		ids.Add(id)

		fls = append(fls, &categoryData{
			url: u,
			id:  id,
		})
	}

	return fls
}
