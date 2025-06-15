package tlsconfig

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// CustomDomainDB is the default local database of custom-domain data.
//
// TODO(a.garipov):  Expand and add handling of certificates on the filesystem.
type CustomDomainDB struct {
	logger *slog.Logger

	// wkPathsMu protects wellKnownPathToExpire.
	wkPathsMu             *sync.RWMutex
	wellKnownPathToExpire map[string]time.Time

	clock   timeutil.Clock
	errColl errcoll.Interface
	strg    CustomDomainStorage
}

// CustomDomainDBConfig contains configuration for the default custom-domain
// database.
type CustomDomainDBConfig struct {
	// Logger is used for logging the operation of custom-domain database.  It
	// must not be nil.
	Logger *slog.Logger

	// Clock is used to check current time.  It must not be nil.
	Clock timeutil.Clock

	// ErrColl is used to collect errors arising during refreshes.  It must not
	// be nil.
	ErrColl errcoll.Interface

	// Storage is used to retrieve the custom-domain data.  It must not be nil.
	//
	// TODO(a.garipov):  Set and use.
	Storage CustomDomainStorage
}

// NewCustomDomainDB returns a properly initialized *CustomDomainDB.  c must not
// be nil and must be valid.
func NewCustomDomainDB(c *CustomDomainDBConfig) (db *CustomDomainDB) {
	return &CustomDomainDB{
		logger:                c.Logger,
		wkPathsMu:             &sync.RWMutex{},
		wellKnownPathToExpire: map[string]time.Time{},
		clock:                 c.Clock,
		errColl:               c.ErrColl,
		strg:                  c.Storage,
	}
}

// type check
var _ profiledb.CustomDomainDB = (*CustomDomainDB)(nil)

// AddCertificate implements the [profiledb.CustomDomainDB] interface
// for *CustomDomainDB.
func (db *CustomDomainDB) AddCertificate(
	ctx context.Context,
	domains []string,
	s *agd.CustomDomainStateCurrent,
) {
	// TODO(a.garipov):  Implement.
}

// DeleteAllWellKnownPaths implements the [profiledb.CustomDomainDB] interface
// for *CustomDomainDB.
func (db *CustomDomainDB) DeleteAllWellKnownPaths(ctx context.Context) {
	db.wkPathsMu.Lock()
	defer db.wkPathsMu.Unlock()

	clear(db.wellKnownPathToExpire)

	db.logger.DebugContext(ctx, "deleted all well-known paths")
}

// SetWellKnownPath implements the [profiledb.CustomDomainDB] interface for
// *CustomDomainDB.
func (db *CustomDomainDB) SetWellKnownPath(ctx context.Context, s *agd.CustomDomainStatePending) {
	db.wkPathsMu.Lock()
	defer db.wkPathsMu.Unlock()

	exp, wkPath := s.Expire, s.WellKnownPath
	if exp.Before(db.clock.Now()) {
		db.logger.DebugContext(ctx, "well-known path expired", "path", wkPath, "exp", exp)

		// There could be a well-known path before, so remove it.
		delete(db.wellKnownPathToExpire, wkPath)

		return
	}

	db.wellKnownPathToExpire[wkPath] = exp

	db.logger.DebugContext(ctx, "set well-known path", "path", wkPath, "exp", exp)
}

// type check
var _ websvc.CertificateValidator = (*CustomDomainDB)(nil)

// IsValidWellKnownRequest implements the [websvc.CertificateValidator]
// interface for *CustomDomainDB.
func (db *CustomDomainDB) IsValidWellKnownRequest(ctx context.Context, r *http.Request) (ok bool) {
	if r.TLS != nil || r.Method != http.MethodGet {
		return false
	}

	db.wkPathsMu.RLock()
	defer db.wkPathsMu.RUnlock()

	p := r.URL.Path
	exp, ok := db.wellKnownPathToExpire[p]
	if !ok {
		return false
	}

	if exp.Before(db.clock.Now()) {
		go db.removeWellKnownPath(ctx, p)

		return false
	}

	return true
}

// removeWellKnownPath removes the well-known path from the profile database.
// It is intended to be used as a goroutine.
//
// TODO(a.garipov):  This and the similar methods in package [profiledb] could
// theoretically remove a path after another refresh has added them, but in
// practice that rarely happens, because refreshes are far apart.  Find a way to
// properly serialize these events.
func (db *CustomDomainDB) removeWellKnownPath(ctx context.Context, wkPath string) {
	defer slogutil.RecoverAndExit(ctx, db.logger, osutil.ExitCodeFailure)

	db.wkPathsMu.Lock()
	defer db.wkPathsMu.Unlock()

	delete(db.wellKnownPathToExpire, wkPath)

	db.logger.DebugContext(ctx, "deleted well-known path", "path", wkPath)
}
