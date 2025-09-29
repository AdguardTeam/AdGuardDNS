package agd

import "time"

// AccountCustomDomains is the configuration for an account's custom domains.
type AccountCustomDomains struct {
	// Domains are the configurations for each set of custom domain names.  All
	// items must not be nil and must be valid.
	Domains []*CustomDomainConfig

	// Enabled shows if the custom-domain feature is enabled for the account.
	Enabled bool
}

// CustomDomainConfig is the configuration of a single set of custom domain
// names with a certificate.
type CustomDomainConfig struct {
	// State is the state of this set of domain names.  It must not be nil.
	State CustomDomainState

	// Domains are the domain names or wildcards in the set.  It must not be
	// empty.
	Domains []string
}

// CustomDomainState is a state of a set of domain names.
//
// The implementations are:
//   - [*CustomDomainStateCurrent]
//   - [*CustomDomainStatePending]
type CustomDomainState interface {
	// isCustomDomainState is a marker method.
	isCustomDomainState()
}

// CustomDomainStateCurrent is the state that a current set of domain names has.
type CustomDomainStateCurrent struct {
	// NotBefore is the time before which the certificate is not valid.  If
	// [CustomDomainStateCurrent.Enabled] is true, it must not be empty and must
	// be strictly before [CustomDomainStateCurrent.NotAfter].
	NotBefore time.Time

	// NotAfter is the time after which the certificate is not valid.  If
	// [CustomDomainStateCurrent.Enabled] is true, it must not be empty and must
	// be strictly after [CustomDomainStateCurrent.NotBefore].
	NotAfter time.Time

	// CertName is the unique name for fetching the actual certificate data.  If
	// [CustomDomainStateCurrent.Enabled] is true, it must not be empty.
	CertName CertificateName

	// Enabled shows if this certificate is enabled.
	Enabled bool
}

// type check
var _ CustomDomainState = (*CustomDomainStateCurrent)(nil)

// isCustomDomainState implements the [CustomDomainState] interface for
// *CustomDomainStateCurrent.
func (*CustomDomainStateCurrent) isCustomDomainState() {}

// CustomDomainStatePending is the state that a set of domain names has when it
// awaits validation.
type CustomDomainStatePending struct {
	// Expire is the expiration time for the data in the state.  It must not be
	// empty.
	Expire time.Time

	// WellKnownPath is the path that should be proxied to the backend for
	// validation.  It must not be empty.
	WellKnownPath string
}

// type check
var _ CustomDomainState = (*CustomDomainStatePending)(nil)

// isCustomDomainState implements the [CustomDomainState] interface for
// *CustomDomainStatePending.
func (*CustomDomainStatePending) isCustomDomainState() {}
