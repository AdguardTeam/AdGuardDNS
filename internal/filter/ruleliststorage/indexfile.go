package ruleliststorage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"slices"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/golibs/errors"
)

// IndexFileConfig is the configuration for the file-based rule list index
// storage.  See [NewIndexFile].
type IndexFileConfig struct {
	// Logger is used to log the inner operations.  It must not be nil.
	Logger *slog.Logger

	// ErrColl is used to collect refresh errors.  It must not be nil.
	ErrColl errcoll.Interface

	// FilePath is the path to the file containing the filter index data.  It
	// must not be empty.
	FilePath string
}

// IndexFile is the [filterindex.RulelistStorage] implementation that works with
// the data stored in files.
type IndexFile struct {
	errColl  errcoll.Interface
	logger   *slog.Logger
	filePath string
}

// NewIndexFile returns a new *IndexFile.  c must be valid.
func NewIndexFile(c *IndexFileConfig) (f *IndexFile) {
	return &IndexFile{
		errColl:  c.ErrColl,
		logger:   c.Logger,
		filePath: c.FilePath,
	}
}

// type check
var _ filterindex.RulelistStorage = (*IndexFile)(nil)

// Rulelist implements the [filterindex.RulelistStorage] interface for
// *IndexFile.
func (f *IndexFile) Rulelist(ctx context.Context) (idx *filterindex.Rulelist, err error) {
	resp, err := f.loadIndex(ctx)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	f.logger.InfoContext(ctx, "loaded index", "num_filters", len(resp.Filters))

	fls := resp.toInternal(ctx, f.logger, f.errColl)
	f.logger.InfoContext(ctx, "validated lists", "num_lists", len(fls))

	return &filterindex.Rulelist{
		Filters: fls,
	}, nil
}

// loadIndex fetches, decodes, and returns the filter list index data.
// resp.Filters are sorted.
func (f *IndexFile) loadIndex(ctx context.Context) (resp *indexResp, err error) {
	f.logger.InfoContext(ctx, "using data from file", "path", f.filePath)

	file, err := os.Open(f.filePath)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, file.Close()) }()

	f.logger.InfoContext(ctx, "got data from file", "path", f.filePath)

	resp = &indexResp{}
	err = json.NewDecoder(file).Decode(resp)
	if err != nil {
		return nil, fmt.Errorf("decoding index: %w", err)
	}

	if len(resp.Filters) == 0 {
		return nil, errors.Error("empty index, not resetting")
	}

	slices.SortStableFunc(resp.Filters, (*indexRespFilter).compare)

	return resp, nil
}
