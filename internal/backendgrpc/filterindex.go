package backendgrpc

import (
	"context"
	"fmt"
	"log/slog"
	"net/http/cookiejar"
	"net/url"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/golibs/timeutil"
)

// FilterIndexStorageConfig is the configuration structure for
// [FilterIndexStorage].
type FilterIndexStorageConfig struct {
	// Logger is used for logging the operation of the filter-index storage.  It
	// must not be nil.
	Logger *slog.Logger

	// Endpoint is the backend API URL.  The scheme should be either "grpc" or
	// "grpcs".  It must not be nil.
	Endpoint *url.URL

	// Clock is used for getting current time.  It must not be nil.
	Clock timeutil.Clock

	// GRPCMetrics is used for the collection of the protobuf communication
	// statistics.
	GRPCMetrics GRPCMetrics

	// Metrics is used for the collection of the filter-index storage
	// statistics.  It must not be nil.
	Metrics FilterIndexStorageMetrics

	// PublicSuffixList is used for obtaining public suffixes of domains.  It
	// must not be nil.
	PublicSuffixList cookiejar.PublicSuffixList

	// APIKey is the API key used for authentication, if any.  If empty, no
	// authentication is performed.
	APIKey string
}

// FilterIndexStorage is an implementation of [filter.IndexStorage] that uses
// the business-logic backend.
type FilterIndexStorage struct {
	logger           *slog.Logger
	endpoint         *url.URL
	client           dnspb.FilterIndexServiceClient
	clock            timeutil.Clock
	grpcMetrics      GRPCMetrics
	metrics          FilterIndexStorageMetrics
	publicSuffixList cookiejar.PublicSuffixList
	apiKey           string
}

// NewFilterIndexStorage returns a new [FilterIndexStorage] that retrieves the
// filter indexes from the business-logic backend.
func NewFilterIndexStorage(c *FilterIndexStorageConfig) (s *FilterIndexStorage, err error) {
	cli, err := newClient(c.Endpoint)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return &FilterIndexStorage{
		logger:           c.Logger,
		endpoint:         c.Endpoint,
		client:           dnspb.NewFilterIndexServiceClient(cli),
		clock:            c.Clock,
		grpcMetrics:      c.GRPCMetrics,
		metrics:          c.Metrics,
		publicSuffixList: c.PublicSuffixList,
		apiKey:           c.APIKey,
	}, nil
}

// type check
var _ filterindex.Storage = (*FilterIndexStorage)(nil)

// Typosquatting implements the [filter.IndexStorage] interface for
// *FilterIndexStorage.
func (s *FilterIndexStorage) Typosquatting(
	ctx context.Context,
) (idx *filterindex.Typosquatting, err error) {
	ctx = ctxWithAuthentication(ctx, s.apiKey)
	req := &dnspb.TyposquattingFilterIndexRequest{}

	startTime := s.clock.Now()
	defer func() {
		// TODO(a.garipov):  Consider separating metrics for networking and
		// decoding.
		s.metrics.ObserveTyposquatting(ctx, s.clock.Now().Sub(startTime), err)
	}()

	resp, err := s.client.GetTyposquattingFilterIndex(ctx, req)
	if err != nil {
		err = fixGRPCError(ctx, s.grpcMetrics, err)
		err = fmt.Errorf("loading typosquatting filter index: %w", err)

		return nil, err
	}

	idx, err = resp.GetIndex().ToInternal(s.publicSuffixList)
	if err != nil {
		return nil, fmt.Errorf("converting typosquatting filter index: %w", err)
	}

	return idx, err
}
