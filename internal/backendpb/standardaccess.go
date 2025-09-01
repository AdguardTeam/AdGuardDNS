package backendpb

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterstorage"
)

// StandardAccessConfig is the configuration structure for the business logic
// backend standard profile access service.
type StandardAccessConfig struct {
	// Logger is used for logging the operation of the standard access service.
	// It must not be nil.
	Logger *slog.Logger

	// GRPCMetrics is used for the collection of the protobuf communication
	// statistics.
	GRPCMetrics GRPCMetrics

	// Metrics is used to collect standard access service statistics.
	Metrics StandardAccessMetrics

	// ErrColl is used to collect errors during procedure calls.
	ErrColl errcoll.Interface

	// Endpoint is the backend API URL.  The scheme should be either "grpc" or
	// "grpcs".  It must not be nil.
	Endpoint *url.URL

	// APIKey is the API key used for authentication, if any.  If empty, no
	// authentication is performed.
	APIKey string
}

// StandardAccess is the implementation of the [service.Refresher] interface
// that retrieves the standard access settings from the business logic backend.
type StandardAccess struct {
	logger      *slog.Logger
	grpcMetrics GRPCMetrics
	metrics     StandardAccessMetrics
	errColl     errcoll.Interface
	client      RateLimitServiceClient
	apiKey      string
}

// NewStandardAccess creates a new properly initialized standard access service.
// c must not be nil.
func NewStandardAccess(c *StandardAccessConfig) (a *StandardAccess, err error) {
	client, err := newClient(c.Endpoint)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return &StandardAccess{
		logger:      c.Logger,
		grpcMetrics: c.GRPCMetrics,
		metrics:     c.Metrics,
		errColl:     c.ErrColl,
		client:      NewRateLimitServiceClient(client),
		apiKey:      c.APIKey,
	}, nil
}

// type check
var _ filterstorage.StandardAccessStorage = (*StandardAccess)(nil)

// Config retrieves the standard access settings from the business logic
// backend.
func (a *StandardAccess) Config(ctx context.Context) (c *access.StandardBlockerConfig, err error) {
	ctx = ctxWithAuthentication(ctx, a.apiKey)
	req := &GlobalAccessSettingsRequest{}

	start := time.Now()
	defer func() {
		// TODO(e.burkov):  Consider separating metrics for networking and
		// decoding.
		a.metrics.ObserveUpdate(ctx, time.Since(start), err)
	}()

	resp, err := a.client.GetGlobalAccessSettings(ctx, req)
	if err != nil {
		return nil, fmt.Errorf(
			"loading global access settings: %w",
			fixGRPCError(ctx, a.grpcMetrics, err),
		)
	}

	return resp.GetStandard().toStandardConfig(ctx, a.logger, a.errColl), nil
}
