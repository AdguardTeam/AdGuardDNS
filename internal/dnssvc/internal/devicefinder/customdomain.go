package devicefinder

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
)

// CustomDomainDB contains information about custom domains and matches domains.
type CustomDomainDB interface {
	// Match returns the domain name or wildcard that matches the client-sent
	// server name.  cliSrvName must be lowercased.
	//
	// If there is a match, matchedDomain must be a valid domain name or
	// wildcard, and profIDs must not be empty and its items must be valid.
	// Otherwise, matchedDomain must be empty and profIDs must be nil.
	//
	// TODO(a.garipov, e.burkov):  Reduce allocations of profIDs.
	Match(ctx context.Context, cliSrvName string) (matchedDomain string, profIDs []agd.ProfileID)
}

// EmptyCustomDomainDB is an [CustomDomainDB] that does nothing.
type EmptyCustomDomainDB struct{}

// type check
var _ CustomDomainDB = EmptyCustomDomainDB{}

// Match implements the [CustomDomainDB] interface for EmptyCustomDomainDB.
// matchedDomain and profID are always empty.
func (EmptyCustomDomainDB) Match(
	_ context.Context,
	_ string,
) (matchedDomain string, profIDs []agd.ProfileID) {
	return "", nil
}
