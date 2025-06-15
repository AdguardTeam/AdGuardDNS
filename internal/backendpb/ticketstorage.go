package backendpb

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/timeutil"
)

// TicketStorageConfig is the configuration structure for [TicketStorage].
type TicketStorageConfig struct {
	// Logger is used for logging the operation of the session ticket storage.
	// It must not be nil.
	Logger *slog.Logger

	// Endpoint is the backend API URL.  The scheme should be either "grpc" or
	// "grpcs".  It must not be nil.
	Endpoint *url.URL

	// GRPCMetrics is used for the collection of the protobuf communication
	// statistics.
	GRPCMetrics GRPCMetrics

	// Metrics is used for the collection of the session ticket storage
	// statistics.  It must not be nil.
	Metrics TicketStorageMetrics

	// Clock is used for getting current time.  It must not be nil.
	Clock timeutil.Clock

	// APIKey is the API key used for authentication, if any.  If empty, no
	// authentication is performed.
	APIKey string
}

// TicketStorage is the [service.Refresher] implementation that retrieves TLS
// session tickets from the backend storage.
type TicketStorage struct {
	logger      *slog.Logger
	endpoint    *url.URL
	grpcMetrics GRPCMetrics
	metrics     TicketStorageMetrics
	client      SessionTicketServiceClient
	clock       timeutil.Clock
	apiKey      string
}

// NewSessionTicketStorage returns a new [TicketStorage] that retrieves
// information from the business logic backend.
func NewSessionTicketStorage(c *TicketStorageConfig) (ts *TicketStorage, err error) {
	cli, err := newClient(c.Endpoint)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return &TicketStorage{
		logger:      c.Logger,
		endpoint:    c.Endpoint,
		grpcMetrics: c.GRPCMetrics,
		metrics:     c.Metrics,
		client:      NewSessionTicketServiceClient(cli),
		clock:       c.Clock,
		apiKey:      c.APIKey,
	}, nil
}

// Tickets implements the [tlsconfig.TicketStorage] interface for
// *SessionTicketStorage.
func (ts *TicketStorage) Tickets(
	ctx context.Context,
) (tickets map[tlsconfig.SessionTicketName]tlsconfig.SessionTicket, err error) {
	ctx = ctxWithAuthentication(ctx, ts.apiKey)
	req := &SessionTicketRequest{}

	startTime := ts.clock.Now()
	defer func() {
		// TODO(e.burkov):  Consider separating metrics for networking and
		// decoding.
		ts.metrics.ObserveUpdate(ctx, ts.clock.Now().Sub(startTime), err)
	}()

	resp, err := ts.client.GetSessionTickets(ctx, req)
	if err != nil {
		err = fmt.Errorf("loading session tickets: %w", fixGRPCError(ctx, ts.grpcMetrics, err))

		return nil, err
	}

	tickets, err = ts.ticketsToInternal(ctx, resp.GetTickets())

	ts.logger.DebugContext(ctx, "loaded session tickets", "count", len(tickets))

	return tickets, err
}
