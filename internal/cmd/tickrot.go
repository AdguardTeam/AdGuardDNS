package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// ticketRotator is a refresh worker that rereads and resets TLS session
// tickets.  It should be initially refreshed before use.
type ticketRotator struct {
	logger  *slog.Logger
	errColl errcoll.Interface
	confs   map[*tls.Config][]string
}

// newTicketRotator creates a new TLS session ticket rotator that rotates
// tickets for the TLS configurations of all servers in grps.
//
// grps must be valid.
func newTicketRotator(
	logger *slog.Logger,
	errColl errcoll.Interface,
	grps []*agd.ServerGroup,
) (tr *ticketRotator) {
	confs := map[*tls.Config][]string{}

	for _, g := range grps {
		t := g.TLS
		if t == nil || len(t.SessionKeys) == 0 {
			continue
		}

		for _, srv := range g.Servers {
			if srv.TLS != nil {
				confs[srv.TLS] = t.SessionKeys
			}
		}
	}

	return &ticketRotator{
		logger:  logger.With(slogutil.KeyPrefix, "tickrot"),
		errColl: errColl,
		confs:   confs,
	}
}

// sessTickLen is the length of a single TLS session ticket key in bytes.
//
// NOTE: Unlike Nginx, Go's crypto/tls doesn't use the random bytes from the
// session ticket keys as-is, but instead hashes these bytes and uses the first
// 48 bytes of the hashed data as the key name, the AES key, and the HMAC key.
const sessTickLen = 32

// type check
var _ agdservice.Refresher = (*ticketRotator)(nil)

// Refresh implements the [agdservice.Refresher] interface for *ticketRotator.
func (r *ticketRotator) Refresh(ctx context.Context) (err error) {
	r.logger.DebugContext(ctx, "refresh started")
	defer r.logger.DebugContext(ctx, "refresh finished")

	defer func() {
		if err != nil {
			errcoll.Collect(ctx, r.errColl, r.logger, "ticket rotation failed", err)
		}
	}()

	for conf, files := range r.confs {
		keys := make([][sessTickLen]byte, 0, len(files))

		for _, fileName := range files {
			var key [sessTickLen]byte
			key, err = readSessionTicketKey(fileName)
			if err != nil {
				metrics.TLSSessionTicketsRotateStatus.Set(0)

				return fmt.Errorf("session ticket for srv %s: %w", conf.ServerName, err)
			}

			keys = append(keys, key)
		}

		if len(keys) == 0 {
			return fmt.Errorf("no session tickets for srv %s in %q", conf.ServerName, files)
		}

		conf.SetSessionTicketKeys(keys)
	}

	metrics.TLSSessionTicketsRotateStatus.Set(1)
	metrics.TLSSessionTicketsRotateTime.SetToCurrentTime()

	return nil
}

// readSessionTicketKey reads a single TLS session ticket key from a file.
func readSessionTicketKey(fn string) (key [sessTickLen]byte, err error) {
	// #nosec G304 -- Trust the file paths that are given to us in the
	// configuration file.
	b, err := os.ReadFile(fn)
	if err != nil {
		return key, fmt.Errorf("reading session ticket: %w", err)
	}

	if len(b) < sessTickLen {
		return key, fmt.Errorf("session ticket in %s: bad len %d, want %d", fn, len(b), sessTickLen)
	}

	return [sessTickLen]byte(b), nil
}
