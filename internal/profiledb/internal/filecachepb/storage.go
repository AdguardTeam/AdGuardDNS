package filecachepb

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/c2h5oh/datasize"
	renameio "github.com/google/renameio/v2"
	"google.golang.org/protobuf/proto"
)

// Storage is the file-cache storage that encodes data using protobuf.
type Storage struct {
	logger    *slog.Logger
	path      string
	respSzEst datasize.ByteSize
}

// New returns a new protobuf-encoded file-cache storage.
func New(logger *slog.Logger, cachePath string, respSzEst datasize.ByteSize) (s *Storage) {
	return &Storage{
		logger:    logger,
		path:      cachePath,
		respSzEst: respSzEst,
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

	return toInternal(fc, s.respSzEst)
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
