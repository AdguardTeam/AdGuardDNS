package backendpb

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
)

// ticketsToInternal converts received session tickets to internal format,
// mapping each ticket to its name.
func (ts *TicketStorage) ticketsToInternal(
	ctx context.Context,
	received []*SessionTicket,
) (tickets map[tlsconfig.SessionTicketName]tlsconfig.SessionTicket, err error) {
	err = validate.NotEmptySlice("received", received)
	if err != nil {
		return nil, err
	}

	tickets = make(map[tlsconfig.SessionTicketName]tlsconfig.SessionTicket, len(received))

	var errs []error
	for i, recTicket := range received {
		name, ticket, convErr := recTicket.toInternal()
		ts.mtrc.SetTicketStatus(ctx, string(name), ts.clock.Now(), convErr)
		if convErr != nil {
			convErr = fmt.Errorf("loaded session ticket: at index %d: %w", i, convErr)
			errs = append(errs, convErr)

			continue
		}

		tickets[name] = ticket
	}

	return tickets, errors.Join(errs...)
}

// toInternal converts the received session ticket to internal format.  It
// always returns non-nil nt, but it may be invalid if the conversion fails.
func (x *SessionTicket) toInternal() (
	name tlsconfig.SessionTicketName,
	ticket tlsconfig.SessionTicket,
	err error,
) {
	var errs []error

	name, err = tlsconfig.NewSessionTicketName(x.GetName())
	if err != nil {
		// Don't wrap the error, since it's informative enough as is.
		errs = append(errs, err)
	}

	ticket, err = tlsconfig.NewSessionTicket(x.GetData())
	if err != nil {
		errs = append(errs, fmt.Errorf("ticket: %w", err))
	}

	return name, ticket, errors.Join(errs...)
}
