package devicefinder

import (
	"context"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
)

// CustomDomainDB contains information about custom domains and matches domains.
type CustomDomainDB interface {
	// Match returns the domain name or wildcard that matches the client-sent
	// server name.  cliSrvName must be lowercased.
	//
	// If there is a match, matchedDomain must be a valid domain name or a
	// wildcard, and accID must be valid.  Otherwise, matchedDomain must be
	// empty and accID must be zero.  accIP is valid only if the matched domain
	// belongs to account IP.
	Match(
		ctx context.Context,
		cliSrvName string,
	) (matchedDomain string, accID agd.AccountID, accIP netip.Addr)
}

// EmptyCustomDomainDB is an [CustomDomainDB] that does nothing.
type EmptyCustomDomainDB struct{}

// type check
var _ CustomDomainDB = EmptyCustomDomainDB{}

// Match implements the [CustomDomainDB] interface for EmptyCustomDomainDB.
// matchedDomain and accIP are always empty, accID is always zero.
func (EmptyCustomDomainDB) Match(
	_ context.Context,
	_ string,
) (matchedDomain string, accID agd.AccountID, accIP netip.Addr) {
	return "", 0, netip.Addr{}
}
