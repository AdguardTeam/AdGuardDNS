package profiledb

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
)

// CustomDomainDB is a database of custom-domain data.  All methods must be safe
// for concurrent use.
type CustomDomainDB interface {
	// AddCertificate adds information about a current certificate.  domains
	// must contain only valid domain names and wildcards like
	// "*.domain.example".  s must not be nil and must be valid.
	AddCertificate(ctx context.Context, domains []string, s *agd.CustomDomainStateCurrent)

	// DeleteAllWellKnownPaths removes all data about well-known paths for
	// certificate validation.
	DeleteAllWellKnownPaths(ctx context.Context)

	// SetWellKnownPath adds a well-known path for certificate validation to the
	// database and sets the expiration time.  s must not be nil and must be
	// valid.
	SetWellKnownPath(ctx context.Context, s *agd.CustomDomainStatePending)
}

// EmptyCustomDomainDB is the implementation of the [CustomDomainDB] interface
// that does nothing.
type EmptyCustomDomainDB struct{}

// type check
var _ CustomDomainDB = EmptyCustomDomainDB{}

// AddCertificate implements the [CustomDomainDB] interface for
// EmptyCustomDomainDB
func (EmptyCustomDomainDB) AddCertificate(
	_ context.Context,
	_ []string,
	_ *agd.CustomDomainStateCurrent,
) {
}

// DeleteAllWellKnownPaths implements the [CustomDomainDB] interface for
// EmptyCustomDomainDB.
func (EmptyCustomDomainDB) DeleteAllWellKnownPaths(_ context.Context) {}

// SetWellKnownPath implements the [CustomDomainDB] interface for
// EmptyCustomDomainDB.
func (EmptyCustomDomainDB) SetWellKnownPath(_ context.Context, _ *agd.CustomDomainStatePending) {}
