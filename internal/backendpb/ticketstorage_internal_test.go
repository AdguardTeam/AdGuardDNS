package backendpb

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/stretchr/testify/assert"
)

func TestTicketStorage_CalcTicketsHash(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		tickets tlsconfig.NamedTickets
		name    string
		want    float64
	}{{
		tickets: tlsconfig.NamedTickets{
			"foo": tlsconfig.SessionTicket{1, 2, 3, 4},
			"bar": tlsconfig.SessionTicket{5, 6, 7, 8},
		},
		name: "data",
		want: 2.5599110696847e+14,
	}, {
		tickets: tlsconfig.NamedTickets{"foo": tlsconfig.SessionTicket{}},
		name:    "no_data",
		want:    1.76700443131662e+14,
	}, {
		tickets: tlsconfig.NamedTickets{},
		name:    "no_tickets",
		want:    0,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, calcTicketsHash(tc.tickets))
		})
	}
}
