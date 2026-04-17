package backendgrpc_test

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/internal/backendtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestTicketStorage_Tickets(t *testing.T) {
	t.Parallel()

	respCh := make(chan *dnspb.SessionTicketResponse, 1)
	errCh := make(chan error, 1)

	srv := &testSessionTicketServiceServer{
		OnGetSessionTickets: func(
			_ context.Context,
			_ *dnspb.SessionTicketRequest,
		) (resp *dnspb.SessionTicketResponse, err error) {
			pt := testutil.NewPanicT(t)

			var ok bool
			resp, ok = testutil.RequireReceive(pt, respCh, backendtest.Timeout)
			require.True(pt, ok)

			err, ok = testutil.RequireReceive(pt, errCh, backendtest.Timeout)
			require.True(pt, ok)

			return resp, err
		},
	}

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(backendtest.Timeout),
		grpc.Creds(insecure.NewCredentials()),
	)
	dnspb.RegisterSessionTicketServiceServer(grpcSrv, srv)
	endpoint := runLocalGRPCServer(t, grpcSrv)
	require.NotNil(t, endpoint)

	storage, err := backendgrpc.NewSessionTicketStorage(&backendgrpc.TicketStorageConfig{
		Logger:      backendtest.Logger,
		Endpoint:    endpoint,
		GRPCMetrics: backendgrpc.EmptyGRPCMetrics{},
		Metrics:     backendgrpc.EmptyTicketStorageMetrics{},
		Clock:       timeutil.SystemClock{},
	})
	require.NoError(t, err)

	const okTicketName tlsconfig.SessionTicketName = "test_ticket"
	okTicketData := tlsconfig.SessionTicket{1, 2, 3, 4}

	require.True(t, t.Run("success", func(t *testing.T) {
		resp := &dnspb.SessionTicketResponse{
			Tickets: []*dnspb.SessionTicket{{
				Name: string(okTicketName),
				Data: okTicketData[:],
			}},
		}

		testutil.RequireSend(t, respCh, resp, backendtest.Timeout)
		testutil.RequireSend(t, errCh, nil, backendtest.Timeout)

		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
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

		const wantErrMsg = `converting: loading session ticket: ` +
			`at index 1: str: at index 4: bad rune '/'` + "\n" +
			`ticket: length: out of range: must be no less than 32, got 4`

		resp := &dnspb.SessionTicketResponse{
			Tickets: []*dnspb.SessionTicket{{
				Name: string(okTicketName),
				Data: okTicketData[:],
			}, {
				Name: string(badTicketName),
				Data: badTicketData[:],
			}},
		}

		testutil.RequireSend(t, respCh, resp, backendtest.Timeout)
		testutil.RequireSend(t, errCh, nil, backendtest.Timeout)

		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
		var tickets tlsconfig.NamedTickets
		tickets, err = storage.Tickets(ctx)
		testutil.AssertErrorMsg(t, wantErrMsg, err)

		require.Contains(t, tickets, okTicketName)

		assert.Len(t, tickets, 1)
		assert.Equal(t, okTicketData, tickets[okTicketName])
		assert.NotContains(t, tickets, badTicketName)
	}))

	require.True(t, t.Run("grpc_error", func(t *testing.T) {
		testutil.RequireSend(t, respCh, nil, backendtest.Timeout)
		testutil.RequireSend(t, errCh, assert.AnError, backendtest.Timeout)

		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
		var tickets tlsconfig.NamedTickets
		tickets, err = storage.Tickets(ctx)
		require.Error(t, err)

		assert.Nil(t, tickets)
	}))
}
