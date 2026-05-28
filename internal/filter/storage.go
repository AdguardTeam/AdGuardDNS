package filter

import (
	"context"
)

// StoragePrefix is a common prefix for logging and refreshes of the filter
// storage.
//
// TODO(a.garipov): Consider extracting these kinds of IDs to agdcache or some
// other package.
const StoragePrefix = "filters/storage"

// Storage is the interface for filter storages that can build a filter based
// on a configuration.
type Storage interface {
	// ForConfig returns a filter created from the configuration.  If c is nil,
	// f is [filter.Empty].
	ForConfig(ctx context.Context, c Config) (f Interface)

	// Dispose returns f to the storage pool for reuse.  f must not be nil.  f
	// must not be used after this call.
	Dispose(f Interface)
}
