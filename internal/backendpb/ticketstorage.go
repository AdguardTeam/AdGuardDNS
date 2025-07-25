package backendpb

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"slices"

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
	if err != nil {
		return tickets, fmt.Errorf("converting: %w", err)
	}

	ts.metrics.SetTicketsState(ctx, calcTicketsHash(tickets))

	return tickets, nil
}

// calcTicketsHash calculates a hash of the tickets and returns a part of it as
// a float64 number.  Returns 0 if there are no tickets.
func calcTicketsHash(tickets tlsconfig.NamedTickets) (num float64) {
	if len(tickets) == 0 {
		return 0
	}

	// Start a new SHA256 hash sum.
	h := sha256.New()

	// Add each ticket's data to the hash sum. The errors are ignored, because
	// [hash.Hash] never returns an error.
	// NOTE:  Sorted by name, as strings, so "ticket_10" goes before "ticket_2".
	for _, name := range slices.Sorted(maps.Keys(tickets)) {
		// NOTE:  Name first, data second, with no separators between them.
		_, _ = h.Write([]byte(name))

		data := tickets[name]
		_, _ = h.Write(data[:])
	}

	hashData := h.Sum(nil)

	// Now, the bytes that will become our uint64 and then float64.
	//
	// NOTE:  Java will have to use a long signed integer here and below, but
	// since we only use 48 bits, there should be no signedness issues.
	intData := make([]byte, 8)

	// Copy the first six bytes to the least significant bytes of the integer
	// data to prevent signedness issues.
	copy(intData[2:8], hashData[0:6])

	// Since we only use 48 bits, the integer should fit into a float64 (aka
	// double in Java) with no issues.
	num = float64(binary.BigEndian.Uint64(intData))

	return num
}
