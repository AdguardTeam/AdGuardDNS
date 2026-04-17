// Package filterindex defines interfaces for indexes of filters.
package filterindex

import "context"

// Storage is the interface for storages of filter indexes.
type Storage interface {
	// Typosquatting returns the current typosquatting-filter index.
	Typosquatting(ctx context.Context) (idx *Typosquatting, err error)
}

// EmptyStorage is an [Storage] that does nothing.
type EmptyStorage struct{}

// type check
var _ Storage = EmptyStorage{}

// Typosquatting implements the [filter.Storage] interface for EmptyStorage.
// idx and err are always nil.
func (EmptyStorage) Typosquatting(_ context.Context) (idx *Typosquatting, err error) {
	return nil, nil
}

// Typosquatting contains domains that must be protected by the typosquatting
// filter, exceptions, etc.
type Typosquatting struct {
	// Domains contains the data about domain names protected by the
	// typosquatting filter.
	Domains []*TyposquattingProtectedDomain

	// Exceptions contains the data about exceptions to the typosquatting
	// filter.
	Exceptions []*TyposquattingException
}

// TyposquattingProtectedDomain is a single protected domain.
type TyposquattingProtectedDomain struct {
	// Domain is the protected domain name, for example "google.com".  It must
	// not be empty and the value must be a valid domain name.  It should be a
	// lowercase eTLD+1 domain.
	Domain string

	// Distance is the minimal Damerau–Levenshtein distance to use when matching
	// against the domain.
	//
	// For example, if distance = 1 and domain = "google.com" then "gogle.com",
	// "gooogle.com", and "gogole.com" will match, but "ggle.com",
	// "goooogle.com", and "ggoole.com" won't.
	//
	// It must be positive.
	Distance uint
}

// TyposquattingException is a single exception to the typosquatting filter.
// For example, if [Typosquatting.Domains] contains "google.com", an exception
// might be "google.co".
type TyposquattingException struct {
	// Domain is the domain name that is skipped by the typosquatting filter.
	// It must not be empty and the value must be a valid domain name.  It
	// should be a lowercase eTLD+1 domain.
	Domain string
}
