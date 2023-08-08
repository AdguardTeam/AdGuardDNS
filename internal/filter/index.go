package filter

import (
	"context"
	"net/url"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
)

// filterIndexResp is the struct for the JSON response from a filter index API.
type filterIndexResp struct {
	Filters []*filterIndexRespFilter `json:"filters"`
}

// filterIndexRespFilter is the struct for a filter from the JSON response from
// a filter index API.
type filterIndexRespFilter struct {
	DownloadURL string `json:"downloadUrl"`
	ID          string `json:"filterId"`
}

// filterIndexFilterData is the data of a single item in the filtering-rule
// index response.
type filterIndexFilterData struct {
	url *url.URL
	id  agd.FilterListID
}

// toInternal converts the filters from the index to []*filterIndexFilterData.
func (r *filterIndexResp) toInternal(
	ctx context.Context,
	errColl agd.ErrorCollector,
) (fls []*filterIndexFilterData) {
	fls = make([]*filterIndexFilterData, 0, len(r.Filters))
	for _, rf := range r.Filters {
		id, err := agd.NewFilterListID(rf.ID)
		if err != nil {
			agd.Collectf(ctx, errColl, "%s: validating id %q: %w", strgLogPrefix, rf.ID, err)

			continue
		}

		var u *url.URL
		u, err = agdhttp.ParseHTTPURL(rf.DownloadURL)
		if err != nil {
			agd.Collectf(
				ctx,
				errColl,
				"%s: validating url %q: %w",
				strgLogPrefix,
				rf.DownloadURL,
				err,
			)

			continue
		}

		fls = append(fls, &filterIndexFilterData{
			url: u,
			id:  id,
		})
	}

	return fls
}
