package filecachepb

import (
	"fmt"
	"os"

	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	renameio "github.com/google/renameio/v2"
	"google.golang.org/protobuf/proto"
)

// Storage is the file-cache storage that encodes data using protobuf.
type Storage struct {
	path string
}

// New returns a new protobuf-encoded file-cache storage.
func New(cachePath string) (s *Storage) {
	return &Storage{
		path: cachePath,
	}
}

// logPrefix is the logging prefix for the protobuf-encoded file-cache.
const logPrefix = "profiledb protobuf cache"

var _ internal.FileCacheStorage = (*Storage)(nil)

// Load implements the [internal.FileCacheStorage] interface for *Storage.
func (s *Storage) Load() (c *internal.FileCache, err error) {
	log.Info("%s: loading", logPrefix)

	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Info("%s: file not present", logPrefix)

			return nil, nil
		}

		return nil, err
	}

	fc := &FileCache{}
	err = proto.Unmarshal(b, fc)
	if err != nil {
		return nil, fmt.Errorf("decoding protobuf: %w", err)
	}

	if fc.Version != internal.FileCacheVersion {
		// Do not decode protobuf file contents in case it probably has
		// unexpected structure.
		return nil, fmt.Errorf(
			"%w: version %d is different from %d",
			internal.CacheVersionError,
			fc.Version,
			internal.FileCacheVersion,
		)
	}

	return toInternal(fc)
}

// Store implements the [internal.FileCacheStorage] interface for *Storage.
func (s *Storage) Store(c *internal.FileCache) (err error) {
	profNum := len(c.Profiles)
	log.Info("%s: saving %d profiles to %q", logPrefix, profNum, s.path)
	defer log.Info("%s: saved %d profiles to %q", logPrefix, profNum, s.path)

	fc := toProtobuf(c)
	b, err := proto.Marshal(fc)
	if err != nil {
		return fmt.Errorf("encoding protobuf: %w", err)
	}

	err = renameio.WriteFile(s.path, b, 0o600)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	return nil
}
