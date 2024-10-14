package filter

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
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
	logger *slog.Logger,
	errColl errcoll.Interface,
) (fls []*filterIndexFilterData) {
	fls = make([]*filterIndexFilterData, 0, len(r.Filters))
	for _, rf := range r.Filters {
		rfFltID, _ := rf.FilterID.(string)
		rfID := cmp.Or(rf.Key, rfFltID)
		id, err := agd.NewFilterListID(rfID)
		if err != nil {
			err = fmt.Errorf("validating id/key: %w", err)
			errcoll.Collect(ctx, errColl, logger, "index response", err)

			continue
		}

		var u *url.URL
		u, err = agdhttp.ParseHTTPURL(rf.DownloadURL)
		if err != nil {
			err = fmt.Errorf("validating url: %w", err)
			errcoll.Collect(ctx, errColl, logger, "index response", err)

			continue
		}

		fls = append(fls, &filterIndexFilterData{
			url: u,
			id:  id,
		})
	}

	return fls
}
