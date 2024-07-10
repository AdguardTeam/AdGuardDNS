package filter

import (
	"cmp"
	"context"
	"net/url"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
)

// filterIndexResp is the struct for the JSON response from a filter index API.
type filterIndexResp struct {
	Filters []*filterIndexRespFilter `json:"filters"`
}

// filterIndexRespFilter is the struct for a filter from the JSON response from
// a filter index API.
//
// TODO(a.garipov):  Remove ID once the index switches the format completely.
type filterIndexRespFilter struct {
	DownloadURL string `json:"downloadUrl"`
	FilterID    any    `json:"filterId"`
	Key         string `json:"filterKey"`
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
	errColl errcoll.Interface,
) (fls []*filterIndexFilterData) {
	fls = make([]*filterIndexFilterData, 0, len(r.Filters))
	for _, rf := range r.Filters {
		rfFltID, _ := rf.FilterID.(string)
		rfID := cmp.Or(rf.Key, rfFltID)
		id, err := agd.NewFilterListID(rfID)
		if err != nil {
			errcoll.Collectf(ctx, errColl, "%s: validating id/key %q: %w", strgLogPrefix, rfID, err)

			continue
		}

		var u *url.URL
		u, err = agdhttp.ParseHTTPURL(rf.DownloadURL)
		if err != nil {
			errcoll.Collectf(
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
