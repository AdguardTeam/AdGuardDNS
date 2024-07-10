package rulelist

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
)

// Immutable is a rule-list filter that doesn't refresh or change.
// It is used for users' custom rule-lists as well as in service blocking.
//
// TODO(a.garipov): Consider not using rule-list engines for service and custom
// filters at all.  It could be faster to simply go through all enabled rules
// sequentially instead.  Alternatively, rework the urlfilter.DNSEngine and make
// it use the sequential scan if the number of rules is less than some constant
// value.
//
// See AGDNS-342.
type Immutable struct {
	// TODO(a.garipov): Find ways to embed it in a way that shows the methods,
	// doesn't result in double dereferences, and doesn't cause naming issues.
	*filter
}

// NewImmutable returns a new immutable DNS request and response filter using
// the provided rule text and ID.
func NewImmutable(
	text string,
	id agd.FilterListID,
	svcID agd.BlockedServiceID,
	cache ResultCache,
) (f *Immutable, err error) {
	f = &Immutable{}
	f.filter, err = newFilter(text, id, svcID, cache)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return f, nil
}
