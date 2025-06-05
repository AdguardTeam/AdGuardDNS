package backendpb_test

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestTicketStorage_Tickets(t *testing.T) {
	t.Parallel()

	var response *backendpb.SessionTicketResponse
	var respErr error
	srv := &testSessionTicketServiceServer{
		OnGetSessionTickets: func(
			ctx context.Context,
			_ *backendpb.SessionTicketRequest,
		) (resp *backendpb.SessionTicketResponse, err error) {
			return response, respErr
		},
	}

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(backendpb.TestTimeout),
		grpc.Creds(insecure.NewCredentials()),
	)
	backendpb.RegisterSessionTicketServiceServer(grpcSrv, srv)
	endpoint := runLocalGRPCServer(t, grpcSrv)

	storage, err := backendpb.NewSessionTicketStorage(&backendpb.TicketStorageConfig{
		Logger:      slogutil.NewDiscardLogger(),
		Endpoint:    endpoint,
		GRPCMetrics: backendpb.EmptyGRPCMetrics{},
		Metrics:     backendpb.EmptyTicketStorageMetrics{},
		Clock:       timeutil.SystemClock{},
	})
	require.NoError(t, err)

	const okTicketName tlsconfig.SessionTicketName = "test_ticket"
	okTicketData := tlsconfig.SessionTicket{1, 2, 3, 4}

	require.True(t, t.Run("success", func(t *testing.T) {
		response, respErr = &backendpb.SessionTicketResponse{
			Tickets: []*backendpb.SessionTicket{{
				Name: string(okTicketName),
				Data: okTicketData[:],
			}},
		}, nil

		ctx := testutil.ContextWithTimeout(t, backendpb.TestTimeout)
		var tickets tlsconfig.NamedTickets
		tickets, err = storage.Tickets(ctx)
		require.NoError(t, err)

		require.Contains(t, tickets, okTicketName)
		assert.Len(t, tickets, 1)
		assert.Equal(t, okTicketData, tickets[okTicketName])
	}))

	require.True(t, t.Run("malformed", func(t *testing.T) {
		const badTicketName tlsconfig.SessionTicketName = "test/ticket"
		badTicketData := []byte{1, 2, 3, 4}

		const wantErrMsg = `loaded session ticket: ` +
			`at index 1: name: at index 4: bad rune '/'` + "\n" +
			`ticket: length: out of range: must be no less than 32, got 4`

		response, respErr = &backendpb.SessionTicketResponse{
			Tickets: []*backendpb.SessionTicket{{
				Name: string(okTicketName),
				Data: okTicketData[:],
			}, {
				Name: string(badTicketName),
				Data: badTicketData[:],
			}},
		}, nil

		ctx := testutil.ContextWithTimeout(t, backendpb.TestTimeout)
		var tickets tlsconfig.NamedTickets
		tickets, err = storage.Tickets(ctx)
		testutil.AssertErrorMsg(t, wantErrMsg, err)

		require.Contains(t, tickets, okTicketName)
		assert.Len(t, tickets, 1)
		assert.Equal(t, okTicketData, tickets[okTicketName])
		assert.NotContains(t, tickets, badTicketName)
	}))

	require.True(t, t.Run("grpc_error", func(t *testing.T) {
		response, respErr = nil, assert.AnError

		ctx := testutil.ContextWithTimeout(t, backendpb.TestTimeout)
		var tickets tlsconfig.NamedTickets
		tickets, err = storage.Tickets(ctx)
		require.Error(t, err)
		assert.Nil(t, tickets)
	}))
}
