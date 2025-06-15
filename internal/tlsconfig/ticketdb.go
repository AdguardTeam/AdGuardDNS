package tlsconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/google/renameio/v2"
)

// TicketStorage is an entity that retrieves the actual TLS session tickets.
type TicketStorage interface {
	// Tickets returns the actual TLS session tickets mapped to their names.  If
	// err is not nil, tickets may still contain useful tickets.
	Tickets(ctx context.Context) (tickets NamedTickets, err error)
}

// TicketDB is an entity which indexes ticket files at the file system and is
// aware of their paths.
type TicketDB interface {
	// Paths returns the paths to TLS session ticket files.
	Paths(ctx context.Context) (paths []string, err error)
}

// LocalTicketDBConfig is the configuration structure for [LocalTicketDB].
type LocalTicketDBConfig struct {
	// Paths are paths to files containing the TLS session tickets.  It should
	// only contain valid paths.
	Paths []string
}

// LocalTicketDB is a local implementation of the [TicketDB] interface.
type LocalTicketDB struct {
	paths []string
}

// type check
var _ TicketDB = (*LocalTicketDB)(nil)

// NewLocalTicketDB returns a new [LocalTicketDB] that retrieves information
// from the local storage.
func NewLocalTicketDB(c *LocalTicketDBConfig) (db *LocalTicketDB) {
	return &LocalTicketDB{
		paths: c.Paths,
	}
}

// Paths implements the [TicketDB] interface for *LocalTicketDB.  It always
// returns a nil error.
func (db *LocalTicketDB) Paths(_ context.Context) (paths []string, err error) {
	return db.paths, nil
}

// RemoteTicketDBConfig is the configuration structure for [RemoteTicketDB].
type RemoteTicketDBConfig struct {
	// Logger is used for logging the operation of the ticket database.
	Logger *slog.Logger

	// Storage is used to retrieve the session tickets.  It must not be nil.
	Storage TicketStorage

	// Clock is the clock used to get the current time.  It must not be nil.
	Clock timeutil.Clock

	// CacheDirPath is the directory where the session tickets are cached.  It
	// must be a valid non-empty path to directory.  If directory doesn't exist,
	// it's created.
	CacheDirPath string

	// IndexFileName is the base name of the index file, stored session tickets
	// shouldn't have this name.  If the file doesn't exist, it's created.  It
	// must not be empty.
	IndexFileName string
}

// RemoteTicketDB is a remote implementation of the [TicketDB] interface.
type RemoteTicketDB struct {
	logger        *slog.Logger
	strg          TicketStorage
	clock         timeutil.Clock
	index         IndexedTickets
	indexFilePath string
	indexFileName string
	cacheDir      string
}

// NewRemoteTicketDB returns a new [TicketDB] that retrieves information from
// the remote storage.
func NewRemoteTicketDB(c *RemoteTicketDBConfig) (db *RemoteTicketDB, err error) {
	err = os.MkdirAll(c.CacheDirPath, 0o700)
	if err != nil {
		return nil, fmt.Errorf("creating cache directory %q: %w", c.CacheDirPath, err)
	}

	db = &RemoteTicketDB{
		logger:        c.Logger,
		strg:          c.Storage,
		clock:         c.Clock,
		indexFilePath: filepath.Join(c.CacheDirPath, c.IndexFileName),
		indexFileName: c.IndexFileName,
		cacheDir:      c.CacheDirPath,
	}

	err = db.initTicketIndex()
	if err != nil {
		return nil, fmt.Errorf("initializing ticket index: %w", err)
	}

	return db, nil
}

// type check
var _ TicketDB = (*RemoteTicketDB)(nil)

// Paths implements the [TicketDB] interface for *RemoteTicketDB.
func (db *RemoteTicketDB) Paths(ctx context.Context) (paths []string, err error) {
	err = db.refresh(ctx)
	if err != nil {
		err = fmt.Errorf("refreshing ticket database: %w", err)

		// Don't return here since there may still be usable tickets in cache.
	}

	for _, name := range slices.Sorted(maps.Keys(db.index)) {
		paths = append(paths, filepath.Join(db.cacheDir, string(name)))
	}

	return paths, err
}

// refresh tries to retrieve the TLS session tickets from the configured
// [TicketStorage], indexes them, and returns.
func (db *RemoteTicketDB) refresh(ctx context.Context) (err error) {
	tickets, err := db.strg.Tickets(ctx)
	if err != nil {
		return fmt.Errorf("retrieving tickets: %w", err)
	}

	if len(tickets) == 0 {
		return fmt.Errorf("received tickets: %w", errors.ErrEmptyValue)
	}

	index := make(IndexedTickets, len(tickets))
	var errs []error
	for name, ticket := range tickets {
		var indexed *IndexedTicket
		indexed, err = db.writeTicketFile(name, ticket)
		if err != nil {
			// Don't wrap the error, since it's informative enough as is.
			errs = append(errs, fmt.Errorf("writing ticket %q: %w", name, err))

			continue
		}

		index[name] = indexed
	}

	db.logger.DebugContext(ctx, "writing tickets", "written", len(index))

	if len(index) > 0 {
		err = db.updateIndex(index)
		if err != nil {
			errs = append(errs, fmt.Errorf("updating index: %w", err))
		}
	}

	return errors.Join(errs...)
}

// writeTicketFile writes a single TLS session ticket to the file system.  The
// ticket is written to the file with the provided name.
func (db *RemoteTicketDB) writeTicketFile(
	name SessionTicketName,
	ticket SessionTicket,
) (it *IndexedTicket, err error) {
	nameStr := string(name)
	if nameStr == db.indexFileName {
		return nil, fmt.Errorf("name: %w: %q; reserved for index", errors.ErrBadEnumValue, name)
	}

	// #nosec G304 -- Trust the file paths that are given to us in the
	// configuration.
	path := filepath.Join(db.cacheDir, nameStr)
	err = renameio.WriteFile(path, ticket[:], 0o600)
	if err != nil {
		return nil, fmt.Errorf("writing ticket file %q: %w", name, err)
	}

	return &IndexedTicket{
		LastUpdate: db.clock.Now(),
	}, nil
}

// TicketIndexVersion is the current schema version of the index file.  It must
// be manually incremented on every change in [StoredIndex] and related types.
const TicketIndexVersion uint = 1

// StoredIndex is a helper type for encoding and decoding the session tickets
// index.
type StoredIndex struct {
	// Tickets are the tickets added to the index.
	Tickets IndexedTickets `json:"tickets"`

	// Version is the schema version of the index file.
	Version uint `json:"version"`
}

// IndexedTickets stores the information about all known session tickets mapped
// to their names.
type IndexedTickets map[SessionTicketName]*IndexedTicket

// IndexedTicket stores the information about a session ticket.
type IndexedTicket struct {
	// LastUpdate is the time when the session ticket has been written the last
	// time.
	LastUpdate time.Time `json:"last_update"`
}

func (db *RemoteTicketDB) initTicketIndex() (err error) {
	filePath := filepath.Join(db.cacheDir, db.indexFileName)

	// #nosec G304 -- Trust the file paths that are given to us in the
	// configuration.
	f, err := os.Open(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return db.updateIndex(IndexedTickets{})
		}

		return fmt.Errorf("opening index file: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, f.Close()) }()

	var index StoredIndex
	err = json.NewDecoder(f).Decode(&index)
	if err != nil {
		return fmt.Errorf("decoding index file %q: %w", filePath, err)
	}

	err = validate.InRange("version", index.Version, TicketIndexVersion, TicketIndexVersion)
	if err != nil {
		return fmt.Errorf("invalid schema version: %w", err)
	}

	db.index = index.Tickets

	return nil
}

// updateIndex updates the index with the provided session tickets.  The index
// is updated only if the provided session tickets are different from the
// current
func (db *RemoteTicketDB) updateIndex(tickets IndexedTickets) (err error) {
	db.index = tickets

	index := &StoredIndex{
		Tickets: tickets,
		Version: TicketIndexVersion,
	}
	buf := &bytes.Buffer{}

	err = json.NewEncoder(buf).Encode(index)
	if err != nil {
		return fmt.Errorf("encoding index file: %w", err)
	}

	err = renameio.WriteFile(db.indexFilePath, buf.Bytes(), 0o600)
	if err != nil {
		return fmt.Errorf("writing index file: %w", err)
	}

	return nil
}
