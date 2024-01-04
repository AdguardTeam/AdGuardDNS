// Package internal contains common constants and types that all implementations
// of the default profile-cache use.
package internal

import (
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/errors"
)

// FileCacheVersion is the version of cached data structure.  It must be
// manually incremented on every change in [agd.Device], [agd.Profile], and any
// file-cache structures.
const FileCacheVersion = 9

// CacheVersionError is returned from [FileCacheStorage.Load] method if the
// stored cache version doesn't match current [FileCacheVersion].
const CacheVersionError errors.Error = "unsuitable cache version"

// FileCache contains the data that is cached on the filesystem.
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
	Load() (c *FileCache, err error)

	// Store writes the data to the cache file.  c must not be nil.  Store must
	// return an informative error.
	Store(c *FileCache) (err error)
}

// EmptyFileCacheStorage is the empty file-cache storage that does nothing and
// returns nils.
type EmptyFileCacheStorage struct{}

// type check
var _ FileCacheStorage = EmptyFileCacheStorage{}

// Load implements the [FileCacheStorage] interface for EmptyFileCacheStorage.
// It does nothing and returns nils.
func (EmptyFileCacheStorage) Load() (_ *FileCache, _ error) { return nil, nil }

// Store implements the [FileCacheStorage] interface for EmptyFileCacheStorage.
// It does nothing and returns nil.
func (EmptyFileCacheStorage) Store(_ *FileCache) (_ error) { return nil }
