package devicefinder

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
)

// CustomDomainDB contains information about custom domains and matches domains.
type CustomDomainDB interface {
	// Match returns the domain name or wildcard that matches the client-sent
	// server name.  If there is a match, matchedDomain must be a valid domain
	// name or wildcard, and profID must not be empty and must be valid.
	// Otherwise, both matchedDomain and profID must be empty.
	Match(ctx context.Context, cliSrvName string) (matchedDomain string, profID agd.ProfileID)
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
) (matchedDomain string, profID agd.ProfileID) {
	return "", ""
}
