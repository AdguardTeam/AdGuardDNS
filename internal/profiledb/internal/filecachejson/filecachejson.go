// Package filecachejson contains an implementation of the file-cache storage
// that encodes data using JSON.
package filecachejson

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	renameio "github.com/google/renameio/v2"
)

// Storage is the file-cache storage that encodes data using JSON.
type Storage struct {
	path string
}

// New returns a new JSON-encoded file-cache storage.
func New(cachePath string) (s *Storage) {
	return &Storage{
		path: cachePath,
	}
}

// fileCache is the structure for the JSON filesystem cache of a profile
// database.
//
// NOTE: Do not change fields of this structure without incrementing
// [internal.FileCacheVersion].
type fileCache struct {
	SyncTime time.Time      `json:"sync_time"`
	Profiles []*agd.Profile `json:"profiles"`
	Devices  []*agd.Device  `json:"devices"`
	Version  int32          `json:"version"`
}

// logPrefix is the logging prefix for the JSON-encoded file-cache.
const logPrefix = "profiledb json cache"

var _ internal.FileCacheStorage = (*Storage)(nil)

// Load implements the [internal.FileCacheStorage] interface for *Storage.
func (s *Storage) Load() (c *internal.FileCache, err error) {
	log.Info("%s: loading", logPrefix)

	data, err := s.loadFromFile()
	if err != nil {
		return nil, fmt.Errorf("loading from file: %w", err)
	}

	if data == nil {
		log.Info("%s: file not present", logPrefix)

		return nil, nil
	}

	if data.Version != internal.FileCacheVersion {
		return nil, fmt.Errorf(
			"%w: version %d is different from %d",
			internal.CacheVersionError,
			data.Version,
			internal.FileCacheVersion,
		)
	}

	return &internal.FileCache{
		SyncTime: data.SyncTime,
		Profiles: data.Profiles,
		Devices:  data.Devices,
		Version:  data.Version,
	}, nil
}

// loadFromFile loads the profile data from cache file.
func (s *Storage) loadFromFile() (data *fileCache, err error) {
	file, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// File could be deleted or not yet created, go on.
			return nil, nil
		}

		return nil, err
	}
	defer func() { err = errors.WithDeferred(err, file.Close()) }()

	data = &fileCache{}
	err = json.NewDecoder(file).Decode(data)
	if err != nil {
		return nil, fmt.Errorf("decoding json: %w", err)
	}

	return data, nil
}

// Store implements the [internal.FileCacheStorage] interface for *Storage.
func (s *Storage) Store(c *internal.FileCache) (err error) {
	profNum := len(c.Profiles)
	log.Info("%s: saving %d profiles to %q", logPrefix, profNum, s.path)
	defer log.Info("%s: saved %d profiles to %q", logPrefix, profNum, s.path)

	data := &fileCache{
		SyncTime: c.SyncTime,
		Profiles: c.Profiles,
		Devices:  c.Devices,
		Version:  c.Version,
	}

	cache, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encoding json: %w", err)
	}

	err = renameio.WriteFile(s.path, cache, 0o600)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	return nil
}
