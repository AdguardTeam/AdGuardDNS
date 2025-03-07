package backendpb

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/AdguardTeam/AdGuardDNS/internal/consul"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/service"
)

// RateLimiterConfig is the configuration structure for the business logic
// backend rate limiter.
type RateLimiterConfig struct {
	// Logger is used for logging the operation of the rate limiter.  It must
	// not be nil.
	Logger *slog.Logger

	// GRPCMetrics is used for the collection of the protobuf communication
	// statistics.
	GRPCMetrics GRPCMetrics

	// Metrics is used to collect allowlist statistics.
	Metrics consul.Metrics

	// Allowlist is the allowlist to update.
	Allowlist *ratelimit.DynamicAllowlist

	// ErrColl is used to collect errors during refreshes.
	ErrColl errcoll.Interface

	// Endpoint is the backend API URL.  The scheme should be either "grpc" or
	// "grpcs".  It must not be nil.
	Endpoint *url.URL

	// APIKey is the API key used for authentication, if any.  If empty, no
	// authentication is performed.
	APIKey string
}

// RateLimiter is the implementation of the [service.Refresher] interface that
// retrieves the rate limit settings from the business logic backend.
type RateLimiter struct {
	logger      *slog.Logger
	grpcMetrics GRPCMetrics
	metrics     consul.Metrics
	allowlist   *ratelimit.DynamicAllowlist
	errColl     errcoll.Interface
	client      RateLimitServiceClient
	apiKey      string
}

// NewRateLimiter creates a new properly initialized rate limiter.  c must not
// be nil.
func NewRateLimiter(c *RateLimiterConfig) (l *RateLimiter, err error) {
	client, err := newClient(c.Endpoint)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return &RateLimiter{
		logger:      c.Logger,
		grpcMetrics: c.GRPCMetrics,
		metrics:     c.Metrics,
		allowlist:   c.Allowlist,
		errColl:     c.ErrColl,
		client:      NewRateLimitServiceClient(client),
		apiKey:      c.APIKey,
	}, nil
}

// type check
var _ service.Refresher = (*RateLimiter)(nil)

// Refresh implements the [service.Refresher] interface for *RateLimiter.
func (l *RateLimiter) Refresh(ctx context.Context) (err error) {
	l.logger.InfoContext(ctx, "refresh started")
	defer l.logger.InfoContext(ctx, "refresh finished")

	defer func() { l.metrics.SetStatus(ctx, err) }()

	ctx = ctxWithAuthentication(ctx, l.apiKey)
	backendResp, err := l.client.GetRateLimitSettings(ctx, &RateLimitSettingsRequest{})
	if err != nil {
		return fmt.Errorf(
			"loading backend rate limit settings: %w",
			fixGRPCError(ctx, l.grpcMetrics, err),
		)
	}

	allowedSubnets := backendResp.AllowedSubnets
	prefixes := cidrRangeToInternal(ctx, l.errColl, l.logger, allowedSubnets)
	l.allowlist.Update(prefixes)

	l.logger.InfoContext(ctx, "refresh successful", "num_records", len(prefixes))

	l.metrics.SetSize(ctx, len(prefixes))

	return nil
}
