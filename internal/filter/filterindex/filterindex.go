// Package filterindex defines interfaces for indexes of filters.
package filterindex

import "context"

// Storage is the interface for storages of filter indexes.
type Storage interface {
	// Typosquatting returns the current typosquatting-filter index.
	Typosquatting(ctx context.Context) (idx *Typosquatting, err error)

	// Homoglyph returns the current homoglyph-filter index.
	Homoglyph(ctx context.Context) (idx *Homoglyph, err error)
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

// Homoglyph implements the [filter.Storage] interface for EmptyStorage.  idx
// and err are always nil.
func (EmptyStorage) Homoglyph(_ context.Context) (idx *Homoglyph, err error) {
	return nil, nil
}
