package rulelist

import "github.com/AdguardTeam/AdGuardDNS/internal/filter"

// Immutable is a rule-list filter that doesn't refresh or change.  It is used
// for users' custom rule-lists as well as in service blocking.
//
// TODO(a.garipov):  Consider not using rule-list engines for service and custom
// filters at all.  It could be faster to simply go through all enabled rules
// sequentially instead.  Alternatively, rework the [urlfilter.DNSEngine] and
// make it use the sequential scan if the number of rules is less than some
// constant value.
//
// See AGDNS-342.
type Immutable struct {
	// TODO(a.garipov):  Find ways to embed it in a way that shows the methods,
	// doesn't result in double dereferences, and doesn't cause naming issues.
	*baseFilter
}

// NewImmutable returns a new immutable DNS request and response filter using
// the provided rule text and IDs.
func NewImmutable(
	text string,
	id filter.ID,
	svcID filter.BlockedServiceID,
	cache ResultCache,
) (f *Immutable) {
	return &Immutable{
		baseFilter: newBaseFilter(text, id, svcID, cache),
	}
}
