package ruleliststorage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/ioutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/c2h5oh/datasize"
)

// IndexHTTPConfig is the configuration for the HTTP-based rule list index
// storage.  See [NewIndexHTTP].
type IndexHTTPConfig struct {
	// Logger is used to log the inner operations.  It must not be nil.
	Logger *slog.Logger

	// ErrColl is used to collect refresh errors.  It must not be nil.
	ErrColl errcoll.Interface

	// URL is the URL used to refresh the data.  It should be HTTP(S) URL and
	// must not be nil.
	URL *url.URL

	// Timeout is the timeout for the HTTP client.  It must be positive.
	Timeout time.Duration

	// MaxSize is the maximum size of the downloadable data.  It must be
	// positive.
	MaxSize datasize.ByteSize
}

// IndexHTTP is the [filterindex.RulelistStorage] implementation that works with
// the data accessible by HTTP.
type IndexHTTP struct {
	errColl errcoll.Interface
	http    *agdhttp.Client
	logger  *slog.Logger
	url     *url.URL
	maxSize datasize.ByteSize
}

// NewIndexHTTP returns a new *IndexHTTP.  c must be valid.
func NewIndexHTTP(c *IndexHTTPConfig) (f *IndexHTTP) {
	return &IndexHTTP{
		errColl: c.ErrColl,
		http: agdhttp.NewClient(&agdhttp.ClientConfig{
			Timeout: c.Timeout,
		}),
		logger:  c.Logger,
		url:     c.URL,
		maxSize: c.MaxSize,
	}
}

// type check
var _ filterindex.RulelistStorage = (*IndexHTTP)(nil)

// Rulelist implements the [filterindex.RulelistStorage] interface for
// *IndexHTTP.
func (h *IndexHTTP) Rulelist(ctx context.Context) (idx *filterindex.Rulelist, err error) {
	resp, err := h.loadIndex(ctx)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	h.logger.InfoContext(ctx, "loaded index", "num_filters", len(resp.Filters))

	fls := resp.toInternal(ctx, h.logger, h.errColl)
	h.logger.InfoContext(ctx, "validated lists", "num_lists", len(fls))

	return &filterindex.Rulelist{
		Filters: fls,
	}, nil
}

// loadIndex fetches, decodes, and returns the filter list index data.
// resp.Filters are sorted.
func (h *IndexHTTP) loadIndex(ctx context.Context) (resp *indexResp, err error) {
	ru := urlutil.RedactUserinfo(h.url)
	h.logger.InfoContext(ctx, "refreshing from url", "url", ru)

	httpResp, err := h.http.Get(ctx, h.url)
	if err != nil {
		return nil, fmt.Errorf("requesting: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, httpResp.Body.Close()) }()

	h.logger.InfoContext(
		ctx,
		"got data from url",
		"code", httpResp.StatusCode,
		"content-length", httpResp.ContentLength,
		"server", httpResp.Header.Get(httphdr.Server),
		"url", ru,
	)

	err = agdhttp.CheckStatus(httpResp, http.StatusOK)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	resp = &indexResp{}
	reader := ioutil.LimitReader(httpResp.Body, h.maxSize.Bytes())
	err = json.NewDecoder(reader).Decode(resp)
	if err != nil {
		return nil, fmt.Errorf("decoding index: %w", err)
	}

	if len(resp.Filters) == 0 {
		return nil, agdhttp.WrapServerError(errors.Error("empty index, not resetting"), httpResp)
	}

	slices.SortStableFunc(resp.Filters, (*indexRespFilter).compare)

	return resp, nil
}
