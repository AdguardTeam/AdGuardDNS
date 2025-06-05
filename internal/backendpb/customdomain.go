package backendpb

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/timeutil"
)

// CustomDomainStorage is the implementation of the
// [tlsconfig.CustomDomainStorage] interface that uses the business-logic
// backend as the custom-domain certificate storage.  It is safe for concurrent
// use.
//
// TODO(a.garipov):  Use.
type CustomDomainStorage struct {
	logger      *slog.Logger
	client      CustomDomainServiceClient
	clock       timeutil.Clock
	grpcMetrics GRPCMetrics
	metrics     CustomDomainStorageMetrics
	apiKey      string
}

// CustomDomainStorageConfig is the configuration for the custom-domain data
// storage.
type CustomDomainStorageConfig struct {
	// Endpoint is the backend API URL.  It must not be nil and the scheme
	// should be either "grpc" or "grpcs".
	Endpoint *url.URL

	// Logger is used for logging the operation of the custom-domain data
	// storage.  It must not be nil.
	Logger *slog.Logger

	// Clock is used to get current time for statistics.  It must not be nil.
	Clock timeutil.Clock

	// GRPCMetrics is used for the collection of the protobuf communication
	// statistics.  It must not be nil.
	GRPCMetrics GRPCMetrics

	// Metrics collects the statistics of the custom-domain certificate storage.
	// It must not be nil.
	Metrics CustomDomainStorageMetrics

	// APIKey is the API key used for authentication, if any.
	APIKey string
}

// NewCustomDomainStorage returns a new custom-domain certificate storage that
// retrieves certificate data from the business-logic backend.
func NewCustomDomainStorage(c *CustomDomainStorageConfig) (s *CustomDomainStorage, err error) {
	client, err := newClient(c.Endpoint)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return &CustomDomainStorage{
		logger:      c.Logger,
		client:      NewCustomDomainServiceClient(client),
		clock:       c.Clock,
		grpcMetrics: c.GRPCMetrics,
		metrics:     c.Metrics,
		apiKey:      c.APIKey,
	}, nil
}

// type check
var _ tlsconfig.CustomDomainStorage = (*CustomDomainStorage)(nil)

// CertificateData implements the [tlsconfig.CustomDomainStorage] interface for
// *CustomDomainStorage.
func (s *CustomDomainStorage) CertificateData(
	ctx context.Context,
	name string,
) (cert, key []byte, err error) {
	start := s.clock.Now()
	defer func() { s.metrics.ObserveRequest(ctx, time.Since(start), err) }()

	s.logger.DebugContext(ctx, "getting cert data", "name", name)

	req := &CustomDomainCertificateRequest{
		CertName: name,
	}

	ctx = ctxWithAuthentication(ctx, s.apiKey)

	resp, err := s.client.GetCustomDomainCertificate(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"getting cert data for name %q: %w",
			name,
			fixGRPCError(ctx, s.grpcMetrics, err),
		)
	}

	// TODO(a.garipov):  Consider validating certificate and private-key date.

	return resp.Certificate, resp.PrivateKey, nil
}
