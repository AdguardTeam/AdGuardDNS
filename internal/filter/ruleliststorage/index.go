package ruleliststorage

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
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
// NOTE:  Keep DownloadURL and TimeUpdated strings instead of unmarshalers to
// make sure that objects with invalid data do not prevent valid objects from
// being used.
type indexRespFilter struct {
	// IsCustom defines if the filter is custom for a client.
	IsCustom *bool `json:"isCustom"`

	// DownloadURL contains the URL to use for downloading this filter.
	DownloadURL string `json:"downloadUrl"`

	// Key contains the ID of the filter as a string.
	Key string `json:"filterKey"`

	// TimeUpdated contains the time when the filter was updated.  It is in the
	// IdxTimeUpdatedFormat format.
	TimeUpdated string `json:"timeUpdated"`
}

// IdxTimeUpdatedFormat is the format of the "timeUpdated" field in the index.
//
// See https://github.com/AdguardTeam/HostlistsRegistry/blame/b7f81a3feb145cf6442da859b9e9d07d96a57fad/hostlists-builder/index.js#L26.
const IdxTimeUpdatedFormat = "2006-01-02T15:04:05-0700"

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

	errs := []error{
		// TODO(a.garipov):  Use urlutil.URL or add IsValidURLString to golibs.
		validate.NotEmpty("downloadUrl", f.DownloadURL),
		validate.NotEmpty("timeUpdated", f.TimeUpdated),
	}

	if _, err = filter.NewID(f.Key); err != nil {
		errs = append(errs, fmt.Errorf("filterKey: %w", err))
	}

	return errors.Join(errs...)
}

// toInternal converts the filters from the index to a map of
// *filterindex.RulelistFilter by filter identifiers.  All errors are logged and
// collected.  logger and errColl must not be nil.
func (r *indexResp) toInternal(
	ctx context.Context,
	logger *slog.Logger,
	errColl errcoll.Interface,
) (fls map[filter.ID]*filterindex.RulelistFilter) {
	fls = make(map[filter.ID]*filterindex.RulelistFilter, len(r.Filters))
	for i, rf := range r.Filters {
		err := rf.validate()
		if err != nil {
			err = fmt.Errorf("validating filter at index %d: %w", i, err)
			errcoll.Collect(ctx, errColl, logger, "index response", err)

			continue
		}

		// Use a simple conversion, since [*indexRespFilter.validate] has
		// already made sure that the ID is valid.
		id := filter.ID(rf.Key)
		if _, ok := fls[id]; ok {
			err = fmt.Errorf("rule-list id: %w: %q", errors.ErrDuplicated, rf.Key)
			errcoll.Collect(ctx, errColl, logger, "index response", err)

			continue
		}

		fl, err := rf.toInternal(id)
		if err != nil {
			errcoll.Collect(ctx, errColl, logger, "index response", err)

			continue
		}

		fls[id] = fl
	}

	return fls
}

// isCustomIDPrefix used to determine custom filters from identifiers.
const isCustomIDPrefix = "custom_"

// toInternal converts the filter from the index to *filterindex.RulelistFilter.
// f must be valid.
func (f *indexRespFilter) toInternal(id filter.ID) (d *filterindex.RulelistFilter, err error) {
	u, err := agdhttp.ParseHTTPURL(f.DownloadURL)
	if err != nil {
		return nil, fmt.Errorf("parsing url: %w", err)
	}

	updTime, err := time.Parse(IdxTimeUpdatedFormat, f.TimeUpdated)
	if err != nil {
		return nil, fmt.Errorf("parsing timeUpdated: %w", err)
	}

	var isCustom bool
	if f.IsCustom == nil {
		isCustom = strings.HasPrefix(string(id), isCustomIDPrefix)
	} else {
		isCustom = *f.IsCustom
	}

	return &filterindex.RulelistFilter{
		DownloadURL: u,
		UpdateTime:  updTime,
		IsCustom:    isCustom,
	}, nil
}
