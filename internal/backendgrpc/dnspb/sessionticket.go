package dnspb

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
)

// TicketResult is the result of the conversion of a protobuf session ticket
// into an internal structure.
type TicketResult struct {
	// Error contains the composite error of all validation errors for the
	// ticket.
	Error error

	// Ticket is the ticket data, if any.
	Ticket tlsconfig.SessionTicket
}

// TicketsToInternal converts received session tickets to internal format,
// mapping each ticket to its name.  pbTickets should not be empty.  All
// elements of pbTickets must not be nil.  Tickets with invalid names are
// renamed using the "bad_ticket_name_%d" pattern.
func TicketsToInternal(
	ctx context.Context,
	pbTickets []*SessionTicket,
) (results map[tlsconfig.SessionTicketName]*TicketResult, err error) {
	err = validate.NotEmptySlice("received", pbTickets)
	if err != nil {
		return nil, err
	}

	results = make(map[tlsconfig.SessionTicketName]*TicketResult, len(pbTickets))

	var errs []error
	for i, pbt := range pbTickets {
		r := &TicketResult{}

		var name tlsconfig.SessionTicketName
		name, r.Ticket, r.Error = pbt.toInternal(i)

		results[name] = r
		errs = append(errs, r.Error)
	}

	return results, errors.Join(errs...)
}

// toInternal converts the received session ticket to internal format.  name is
// never empty.
func (x *SessionTicket) toInternal(idx int) (
	name tlsconfig.SessionTicketName,
	ticket tlsconfig.SessionTicket,
	err error,
) {
	var errs []error

	name, err = tlsconfig.NewSessionTicketName(x.GetName())
	if err != nil {
		// Don't wrap the error, since it's informative enough as is.
		errs = append(errs, err)

		name = tlsconfig.SessionTicketName(fmt.Sprintf("bad_ticket_name_%d", idx))
	}

	ticket, err = tlsconfig.NewSessionTicket(x.GetData())
	if err != nil {
		errs = append(errs, fmt.Errorf("ticket: %w", err))
	}

	if len(errs) == 0 {
		return name, ticket, nil
	}

	err = errors.Join(errs...)

	return name, ticket, fmt.Errorf("loading session ticket: at index %d: %w", idx, err)
}
