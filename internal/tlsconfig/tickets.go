package tlsconfig

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/prometheus/common/model"
)

// SessionTicketLen is the length of a single TLS session ticket key in bytes.
//
// NOTE: Unlike Nginx, Go's crypto/tls doesn't use the random bytes from the
// session ticket keys as-is, but instead hashes these bytes and uses the first
// 48 bytes of the hashed data as the key name, the AES key, and the HMAC key.
const SessionTicketLen = 32

// SessionTicket is a type alias for a single TLS session ticket.
type SessionTicket = [SessionTicketLen]byte

// NewSessionTicket returns a new TLS session ticket from the provided data, if
// it's valid.
func NewSessionTicket(data []byte) (ticket SessionTicket, err error) {
	err = validate.NoLessThan("length", len(data), SessionTicketLen)
	if err != nil {
		return SessionTicket{}, err
	}

	return SessionTicket(data[:SessionTicketLen]), nil
}

// readSessionTicketFile reads a single TLS session ticket from a file.
func readSessionTicketFile(fn string) (ticket SessionTicket, err error) {
	// #nosec G304 -- Trust the file paths that are given to us in the
	// configuration file.
	b, err := os.ReadFile(fn)
	if err != nil {
		return SessionTicket{}, fmt.Errorf("reading session ticket: %w", err)
	}

	ticket, err = NewSessionTicket(b)
	if err != nil {
		return SessionTicket{}, fmt.Errorf("session ticket in %q: %w", fn, err)
	}

	return ticket, nil
}

// SessionTicketName is a type for the name of a TLS session ticket.  A valid
// SessionTicketName may be used as a file name as well as metrics label.
type SessionTicketName string

// NewSessionTicketName creates a new session ticket name.  It returns an error
// if the provided name is not valid.
func NewSessionTicketName(nameStr string) (name SessionTicketName, err error) {
	err = validate.NotEmpty("name", nameStr)
	if err != nil {
		return "", err
	}

	if i := strings.IndexRune(nameStr, os.PathSeparator); i >= 0 {
		return "", fmt.Errorf("name: at index %d: bad rune %q", i, os.PathSeparator)
	}

	if !model.LabelName(nameStr).IsValid() {
		return "", fmt.Errorf("name: not a valid label: %q", nameStr)
	}

	return SessionTicketName(nameStr), nil
}

// NamedTickets is a set of TLS session tickets mapped to their names.
type NamedTickets = map[SessionTicketName]SessionTicket

// TicketStorage is an entity that retrieves the actual TLS session tickets.
type TicketStorage interface {
	// Tickets returns the actual TLS session tickets mapped to their names.  If
	// err is not nil, tickets may still contain useful tickets.
	Tickets(ctx context.Context) (tickets NamedTickets, err error)
}

// TicketDB is an entity which indexes ticket files at the file system and is
// aware of their paths.
type TicketDB interface {
	// Refresher updates the ticket database.
	service.Refresher

	// Paths returns the paths to TLS session ticket files.
	Paths(ctx context.Context) (paths []string)
}

// LocalTicketDBConfig is the configuration structure for [LocalTicketDB].
type LocalTicketDBConfig struct {
	// Paths are paths to files containing the TLS session tickets.  It should
	// only contain valid paths.
	Paths []string
}

// LocalTicketDB is a local implementation of the [TicketDB] interface.
type LocalTicketDB struct {
	service.EmptyRefresher

	paths []string
}

// type check
var _ TicketDB = (*LocalTicketDB)(nil)

// NewLocalTicketDB returns a new [LocalTicketDB] that retrieves information
// from the local storage.
func NewLocalTicketDB(c *LocalTicketDBConfig) (ts *LocalTicketDB) {
	return &LocalTicketDB{
		paths: c.Paths,
	}
}

// Paths implements the [TicketDB] interface for *LocalTicketDB.
func (ts *LocalTicketDB) Paths(_ context.Context) (paths []string) {
	return ts.paths
}
