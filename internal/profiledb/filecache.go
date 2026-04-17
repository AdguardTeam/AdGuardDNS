package profiledb

import (
	"context"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/c2h5oh/datasize"
)

// FileCache contains the data that is cached on the filesystem.  The Profiles
// and Devices may be modified after being passed to [FileCacheStorage.Store].
type FileCache struct {
	SyncTime time.Time
	Profiles []*agd.Profile
	Devices  []*agd.Device
	Version  int32
}

// FileCacheStorage is the interface for all file caches.
type FileCacheStorage interface {
	// Load read the data from the cache file.  If the file does not exist, Load
	// must return a nil *FileCache.  Load must return an informative error.
	Load(ctx context.Context) (c *FileCache, err error)

	// Store writes the data to the cache file.  c must not be nil.  Returns the
	// length of the written file and error.  The returned error must be
	// informative.
	Store(ctx context.Context, c *FileCache) (n datasize.ByteSize, err error)
}

// EmptyFileCacheStorage is the empty file-cache storage that does nothing and
// returns nils.
type EmptyFileCacheStorage struct{}

// type check
var _ FileCacheStorage = EmptyFileCacheStorage{}

// Load implements the [FileCacheStorage] interface for EmptyFileCacheStorage.
// It does nothing and returns nils.
func (EmptyFileCacheStorage) Load(_ context.Context) (_ *FileCache, _ error) { return nil, nil }

// Store implements the [FileCacheStorage] interface for EmptyFileCacheStorage.
// It does nothing and returns nil.
func (EmptyFileCacheStorage) Store(_ context.Context, _ *FileCache) (_ datasize.ByteSize, _ error) {
	return 0, nil
}
