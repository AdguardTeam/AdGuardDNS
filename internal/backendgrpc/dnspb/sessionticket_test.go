package dnspb_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/internal/backendtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// testTicketName is a test name for the [SessionTicket].
	testTicketName = "test_ticket_name"

	// testTicketData is a test set of data for the [SessionTicket].
	testTicketData = "test_ticketdata_tickettest_ticket"

	// testInvalidTicketData is a test set of invalid data for the
	// [SessionTicket].
	testInvalidTicketData = "invalid_ticket_data"
)

func TestTicketsToInternal(t *testing.T) {
	t.Parallel()

	ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)

	testCases := []struct {
		want       map[tlsconfig.SessionTicketName]*dnspb.TicketResult
		name       string
		wantErrMsg string
		pbTickets  []*dnspb.SessionTicket
	}{{
		name: "success",
		pbTickets: []*dnspb.SessionTicket{{
			Name: testTicketName,
			Data: []byte(testTicketData),
		}},
		want: map[tlsconfig.SessionTicketName]*dnspb.TicketResult{
			testTicketName: {
				Ticket: tlsconfig.SessionTicket([]byte(testTicketData)),
			},
		},
		wantErrMsg: "",
	}, {
		name: "empty_ticket_name",
		pbTickets: []*dnspb.SessionTicket{
			{
				Name: "",
				Data: []byte(testTicketData),
			},
		},
		want: map[tlsconfig.SessionTicketName]*dnspb.TicketResult{
			"bad_ticket_name_0": {
				Ticket: tlsconfig.SessionTicket([]byte(testTicketData)),
				Error:  errors.Error("loading session ticket: at index 0: str: empty value"),
			},
		},
		wantErrMsg: "loading session ticket: at index 0: str: empty value",
	}, {
		name: "invalid_ticket_data",
		pbTickets: []*dnspb.SessionTicket{{
			Name: testTicketName,
			Data: []byte(testInvalidTicketData),
		}},
		want: map[tlsconfig.SessionTicketName]*dnspb.TicketResult{
			testTicketName: {
				Ticket: tlsconfig.SessionTicket{},
				Error: errors.Error("loading session ticket: at index 0: ticket: length: " +
					"out of range: must be no less than 32, got 19",
				),
			},
		},
		wantErrMsg: "loading session ticket: at index 0: ticket: length: " +
			"out of range: must be no less than 32, got 19",
	}, {
		name: "empty_ticket_name_and_invalid_data",
		pbTickets: []*dnspb.SessionTicket{
			{
				Name: "",
				Data: []byte(testInvalidTicketData),
			},
		},
		want: map[tlsconfig.SessionTicketName]*dnspb.TicketResult{
			"bad_ticket_name_0": {
				Ticket: tlsconfig.SessionTicket{},
				Error: errors.Error(`loading session ticket: at index 0: str: empty value` + "\n" +
					`ticket: length: out of range: must be no less than 32, got 19`,
				),
			},
		},
		wantErrMsg: `loading session ticket: at index 0: str: empty value` + "\n" +
			`ticket: length: out of range: must be no less than 32, got 19`,
	}, {
		name:       "empty_slice",
		pbTickets:  []*dnspb.SessionTicket{},
		want:       nil,
		wantErrMsg: "received: empty value",
	}, {
		name:       "nil_slice",
		pbTickets:  nil,
		want:       nil,
		wantErrMsg: "received: no value",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := dnspb.TicketsToInternal(ctx, tc.pbTickets)
			EqualSessionTicketMap(t, tc.want, got)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

// EqualSessionTicketMap is test helper.  It compares two maps of
// [tlsconfig.SessionTicketName]*dnspb.TicketResult with each other.
func EqualSessionTicketMap(
	tb testing.TB,
	want map[tlsconfig.SessionTicketName]*dnspb.TicketResult,
	got map[tlsconfig.SessionTicketName]*dnspb.TicketResult,
) {
	tb.Helper()

	require.Equal(tb, len(want), len(got))

	for wantTicket, wantResult := range want {
		gotResult, ok := got[wantTicket]
		require.True(tb, ok)
		assert.Equal(tb, wantResult.Ticket, gotResult.Ticket)

		if wantResult.Error != nil {
			assert.EqualError(tb, gotResult.Error, wantResult.Error.Error())
		} else {
			assert.NoError(tb, gotResult.Error)
		}
	}
}
