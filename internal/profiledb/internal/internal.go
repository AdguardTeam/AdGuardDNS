// Package internal contains common constants and types that all implementations
// of the default profile-cache use.
package internal

import "github.com/AdguardTeam/golibs/errors"

// FileCacheVersion is the version of cached data structure.  It must be
// manually incremented on every change in [agd.Device], [agd.Profile], and any
// file-cache structures.
//
// Please document the changes to this constant in the changelog.
const FileCacheVersion = 19

// CacheVersionError is returned from [FileCacheStorage.Load] method if the
// stored cache version doesn't match current [FileCacheVersion].
const CacheVersionError errors.Error = "unsuitable cache version"
