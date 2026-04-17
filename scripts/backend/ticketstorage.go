package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"google.golang.org/grpc/metadata"
)

// mockSessionTicketServiceServer is the mock
// [dnspb.SessionTicketServiceServer].
type mockSessionTicketServiceServer struct {
	dnspb.UnimplementedSessionTicketServiceServer
	log *slog.Logger
}

// newMockSessionTicketServiceServer creates a new instance of
// *mockSessionTicketServiceServer.
func newMockSessionTicketServiceServer(log *slog.Logger) (srv *mockSessionTicketServiceServer) {
	return &mockSessionTicketServiceServer{
		log: log,
	}
}

// type check
var _ dnspb.SessionTicketServiceServer = (*mockSessionTicketServiceServer)(nil)

// Get implements the [dnspb.SessionTicketServiceServer] interface for
// *mockSessionTicketServiceServer.
func (s *mockSessionTicketServiceServer) GetSessionTickets(
	ctx context.Context,
	req *dnspb.SessionTicketRequest,
) (resp *dnspb.SessionTicketResponse, err error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.log.InfoContext(
		ctx,
		"getting",
		"auth", md.Get(httphdr.Authorization),
		"req", req,
	)

	const (
		// ticketCount is the number of tickets to generate.
		ticketCount = 7

		// ticketLen is the length of each ticket.  Use 80 bytes to test
		// handling of tickets, that are longer than needed.
		ticketLen = 80
	)

	tickets := make([]*dnspb.SessionTicket, 0, ticketCount)
	for i := range ticketCount {
		var ticket [ticketLen]byte
		_ = errors.Must(rand.Read(ticket[:]))

		tickets = append(tickets, &dnspb.SessionTicket{
			Name: fmt.Sprintf("ticket_%d", i),
			Data: ticket[:],
		})
	}

	resp = &dnspb.SessionTicketResponse{
		Tickets: tickets,
	}

	return resp, nil
}
