package filecachepb

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/c2h5oh/datasize"
	renameio "github.com/google/renameio/v2"
	"google.golang.org/protobuf/proto"
)

// Storage is the file-cache storage that encodes data using protobuf.
type Storage struct {
	logger           *slog.Logger
	baseCustomLogger *slog.Logger
	profAccessCons   *access.ProfileConstructor
	path             string
	respSzEst        datasize.ByteSize
}

// Config is the configuration structure for the protobuf-encoded file-cache
// storage.
type Config struct {
	// Logger is used for logging the operation of profile database.  It must
	// not be nil.
	Logger *slog.Logger

	// BaseCustomLogger is the base logger used for the custom filters.  It must
	// not be nil.
	BaseCustomLogger *slog.Logger

	// ProfileAccessConstructor is used to create access managers for profiles.
	// It must not be nil.
	ProfileAccessConstructor *access.ProfileConstructor

	// CacheFilePath is the path to the profile cache file.  It must be set.
	CacheFilePath string

	// ResponseSizeEstimate is the estimate of the size of one DNS response for
	// the purposes of custom ratelimiting.  Responses over this estimate are
	// counted as several responses.  It must be positive.
	ResponseSizeEstimate datasize.ByteSize
}

// New returns a new protobuf-encoded file-cache storage.  c must not be nil and
// must be valid.
func New(c *Config) (s *Storage) {
	return &Storage{
		logger:           c.Logger,
		baseCustomLogger: c.BaseCustomLogger,
		profAccessCons:   c.ProfileAccessConstructor,
		path:             c.CacheFilePath,
		respSzEst:        c.ResponseSizeEstimate,
	}
}

var _ internal.FileCacheStorage = (*Storage)(nil)

// Load implements the [internal.FileCacheStorage] interface for *Storage.
func (s *Storage) Load(ctx context.Context) (c *internal.FileCache, err error) {
	s.logger.InfoContext(ctx, "loading")

	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.logger.WarnContext(ctx, "file not found")

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

	return toInternal(fc, s.baseCustomLogger, s.profAccessCons, s.respSzEst)
}

// Store implements the [internal.FileCacheStorage] interface for *Storage.
func (s *Storage) Store(ctx context.Context, c *internal.FileCache) (err error) {
	profNum := len(c.Profiles)

	s.logger.InfoContext(ctx, "saving profiles", "path", s.path, "num", profNum)
	defer s.logger.InfoContext(ctx, "saved profiles", "path", s.path, "num", profNum)

	fc := toProtobuf(c)
	b, err := proto.Marshal(fc)
	if err != nil {
		return fmt.Errorf("encoding protobuf: %w", err)
	}

	// Don't wrap the error, because it's informative enough as is.
	return renameio.WriteFile(s.path, b, 0o600)
}
