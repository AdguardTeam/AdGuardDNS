package tlsconfig

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/osutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/google/renameio/v2"
)

// CustomDomainDB is the default local database of custom-domain data.
type CustomDomainDB struct {
	logger *slog.Logger

	// wellKnownPathsMu protects wellKnownPathToExpire.
	wellKnownPathsMu      *sync.RWMutex
	wellKnownPathToExpire map[string]time.Time

	// customCertsMu protects customCerts.
	customCertsMu *sync.RWMutex
	customCerts   *customDomainIndex

	clock   timeutil.Clock
	errColl errcoll.Interface
	metrics CustomDomainDBMetrics
	manager Manager
	strg    CustomDomainStorage

	cacheDir string

	initRetryIvl time.Duration
	maxRetryIvl  time.Duration
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

	// Manager is used to add new domains to it.  It must not be nil.
	Manager Manager

	// Metrics collect the statistics of the custom-domain database.  It must
	// not be nil.
	Metrics CustomDomainDBMetrics

	// Storage is used to retrieve the custom-domain data.  It must not be nil.
	Storage CustomDomainStorage

	// CacheDirPath is the directory where the certificates are cached.  It must
	// be a valid, non-empty path to a directory.  If the directory doesn't
	// exist, it is created.
	CacheDirPath string

	// InitialRetryIvl is the initial interval for retrying a failed cert after
	// a network or a ratelimiting error.  It must be positive.
	InitialRetryIvl time.Duration

	// MaxRetryIvl is the maximum interval between retries.  It must be positive
	// and larger than InitialRetryIvl.
	MaxRetryIvl time.Duration
}

// NewCustomDomainDB returns a properly initialized *CustomDomainDB.  c must not
// be nil and must be valid.
func NewCustomDomainDB(c *CustomDomainDBConfig) (db *CustomDomainDB, err error) {
	err = os.MkdirAll(c.CacheDirPath, 0o700)
	if err != nil {
		return nil, fmt.Errorf("creating cache directory: %w", err)
	}

	return &CustomDomainDB{
		logger: c.Logger,

		wellKnownPathsMu:      &sync.RWMutex{},
		wellKnownPathToExpire: map[string]time.Time{},

		customCertsMu: &sync.RWMutex{},
		customCerts:   newCustomDomainIndex(),

		clock:   c.Clock,
		errColl: c.ErrColl,
		manager: c.Manager,
		metrics: c.Metrics,
		strg:    c.Storage,

		cacheDir: c.CacheDirPath,

		initRetryIvl: c.InitialRetryIvl,
		maxRetryIvl:  c.MaxRetryIvl,
	}, nil
}

// type check
var _ profiledb.CustomDomainDB = (*CustomDomainDB)(nil)

// AddCertificate implements the [profiledb.CustomDomainDB] interface
// for *CustomDomainDB.
func (db *CustomDomainDB) AddCertificate(
	ctx context.Context,
	profID agd.ProfileID,
	domains []string,
	state *agd.CustomDomainStateCurrent,
) {
	startTime := db.clock.Now()
	defer func() {
		const op = CustomDomainDBMetricsOpAddCertificate
		db.metrics.ObserveOperation(ctx, op, db.clock.Now().Sub(startTime))

		db.customCertsMu.RLock()
		defer db.customCertsMu.RUnlock()

		db.metrics.SetCurrentCustomDomainsCount(ctx, uint(db.customCerts.currentCount()))
	}()

	certName := state.CertName
	l := db.logger.With("cert_name", certName, "prof_id", profID)

	if !state.Enabled {
		l.DebugContext(ctx, "certificate is disabled")

		db.removeCertData(ctx, l, certName, profID, domains, "stale")

		return
	}

	if startTime.After(state.NotAfter) {
		l.DebugContext(ctx, "certificate is stale", "not_after", state.NotAfter)

		db.removeCertData(ctx, l, certName, profID, domains, "stale")

		return
	}

	l.DebugContext(ctx, "saving certificate")

	db.customCertsMu.Lock()
	defer db.customCertsMu.Unlock()

	db.customCerts.add(ctx, l, profID, domains, state)
}

// removeCertData deletes the certificate data from the index, the manager, and
// from the filesystem.  Errors are logged and reported to Sentry.
func (db *CustomDomainDB) removeCertData(
	ctx context.Context,
	l *slog.Logger,
	certName agd.CertificateName,
	profID agd.ProfileID,
	domains []string,
	reason string,
) {
	func() {
		db.customCertsMu.Lock()
		defer db.customCertsMu.Unlock()

		db.customCerts.remove(ctx, l, certName, profID, domains)
	}()

	var errs []error
	certPath, keyPath := db.cachePaths(certName)
	err := db.manager.Remove(ctx, certPath, keyPath, true)
	if err != nil {
		errs = append(errs, fmt.Errorf("removing from manager: %w", err))
	}

	l.InfoContext(ctx, "removed from index and manager")

	err = os.Remove(certPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("removing cert file: %w", err))
	} else {
		l.DebugContext(ctx, "removed cert file")
	}

	err = os.Remove(keyPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("removing key file: %w", err))
	} else {
		l.DebugContext(ctx, "removed key file")
	}

	err = errors.Join(errs...)
	if err == nil {
		return
	}

	err = fmt.Errorf("removing cert %q: %w", certName, err)
	msg := fmt.Sprintf("removing %s cert", reason)
	errcoll.Collect(ctx, db.errColl, l, msg, err)
}

// Custom-domain file extensions.
const (
	CustomDomainCertExt = ".crt.pem"
	CustomDomainKeyExt  = ".key.pem"
)

// cachePaths returns the cache paths for the given certificate name.
func (db *CustomDomainDB) cachePaths(certName agd.CertificateName) (certPath, keyPath string) {
	certPath = filepath.Join(db.cacheDir, string(certName)+".crt.pem")
	keyPath = filepath.Join(db.cacheDir, string(certName)+".key.pem")

	return certPath, keyPath
}

// DeleteAllWellKnownPaths implements the [profiledb.CustomDomainDB] interface
// for *CustomDomainDB.
func (db *CustomDomainDB) DeleteAllWellKnownPaths(ctx context.Context) {
	db.wellKnownPathsMu.Lock()
	defer db.wellKnownPathsMu.Unlock()

	clear(db.wellKnownPathToExpire)

	db.metrics.SetWellKnownPathsCount(ctx, 0)

	db.logger.DebugContext(ctx, "deleted all well-known paths")
}

// SetWellKnownPath implements the [profiledb.CustomDomainDB] interface for
// *CustomDomainDB.
func (db *CustomDomainDB) SetWellKnownPath(ctx context.Context, s *agd.CustomDomainStatePending) {
	db.wellKnownPathsMu.Lock()
	defer db.wellKnownPathsMu.Unlock()

	defer func() {
		db.metrics.SetWellKnownPathsCount(ctx, uint(len(db.wellKnownPathToExpire)))
	}()

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

	db.wellKnownPathsMu.RLock()
	defer db.wellKnownPathsMu.RUnlock()

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

	db.wellKnownPathsMu.Lock()
	defer db.wellKnownPathsMu.Unlock()

	delete(db.wellKnownPathToExpire, wkPath)

	db.logger.DebugContext(ctx, "deleted well-known path", "path", wkPath)
}

// type check
var _ dnssvc.CustomDomainDB = (*CustomDomainDB)(nil)

// Match implements the [dnssvc.CustomDomainDB] interface for *CustomDomainDB.
func (db *CustomDomainDB) Match(
	ctx context.Context,
	cliSrvName string,
) (matchedDomain string, profIDs []agd.ProfileID) {
	startTime := db.clock.Now()
	defer func() {
		const op = CustomDomainDBMetricsOpMatch
		db.metrics.ObserveOperation(ctx, op, db.clock.Now().Sub(startTime))
	}()

	db.customCertsMu.RLock()
	defer db.customCertsMu.RUnlock()

	return db.customCerts.match(ctx, db.logger, cliSrvName, startTime)
}

// type check
var _ service.Refresher = (*CustomDomainDB)(nil)

// Refresh implements the [service.Refresher] interface for *CustomDomainDB.
// Refresh will retry network and ratelimiting errors.
func (db *CustomDomainDB) Refresh(ctx context.Context) (err error) {
	var updatedCertNames []agd.CertificateName
	retries := map[agd.CertificateName]*customDomainRetry{}
	func() {
		db.customCertsMu.Lock()
		defer db.customCertsMu.Unlock()

		updatedCertNames = slices.Clone(db.customCerts.changed.Values())
		db.customCerts.changed.Clear()

		maps.Copy(retries, db.customCerts.retries)
		clear(db.customCerts.retries)
	}()

	if len(updatedCertNames) == 0 && len(retries) == 0 {
		db.logger.Log(ctx, slogutil.LevelTrace, "no certs to update or retry")

		return nil
	}

	defer func() {
		db.customCertsMu.Lock()
		defer db.customCertsMu.Unlock()

		db.customCerts.retries = retries
	}()

	var errs []error
	now := db.clock.Now()
	for _, certName := range updatedCertNames {
		var needsRetry bool
		needsRetry, err = db.refreshCert(ctx, certName)
		if err != nil {
			err = fmt.Errorf("refreshing cert %q: %w", certName, err)
			errs = append(errs, err)
		}

		if needsRetry {
			db.addRetry(ctx, retries, certName, now)
		}
	}

	err = errors.Join(errs...)
	if err != nil {
		errcoll.Collect(ctx, db.errColl, db.logger, "refreshing certs", err)

		return fmt.Errorf("refreshing certs: %w", err)
	}

	db.performRetries(ctx, retries, now)

	return nil
}

// refreshCert obtains the data for the certificate with the given name,
// validates it, saves it to disk, and adds it to the manager.  If needsRetry is
// true, refreshCert should be retried later.
func (db *CustomDomainDB) refreshCert(
	ctx context.Context,
	certName agd.CertificateName,
) (needsRetry bool, err error) {
	l := db.logger.With("cert_name", certName)

	certPath, keyPath := db.cachePaths(certName)
	if !db.needsRefresh(ctx, certName, certPath, keyPath) {
		l.Log(ctx, slogutil.LevelTrace, "refresh not needed")

		// Add to the manager in case this is an initial refresh.
		//
		// TODO(a.garipov):  Consider splitting away the initial refresh logic.
		err = db.manager.Add(ctx, certPath, keyPath, true)
		if err != nil {
			return false, fmt.Errorf("adding previous cert to manager: %w", err)
		}

		return false, nil
	}

	certData, keyData, err := db.strg.CertificateData(ctx, certName)
	if err != nil {
		// ErrCertificateNotFound means that the certificate has likely been
		// deleted in the meantime, so do not retry if it is this error.  Retry
		// on all other errors, including ratelimiting ones.
		needsRetry = !errors.Is(err, ErrCertificateNotFound)

		return needsRetry, fmt.Errorf("getting data: %w", err)
	}

	l.InfoContext(ctx, "got data", "cert_len", len(certData), "key_len", len(keyData))

	err = db.saveCertData(ctx, l, certPath, certData, keyPath, keyData)
	if err != nil {
		return false, fmt.Errorf("saving cert %q: %w", certName, err)
	}

	l.InfoContext(ctx, "added certificate")

	return false, nil
}

// saveCertData saves the certificate data to disk in the PEM format and adds it
// to the TLS manager.  l must not be nil.  certPath and keyPath must be valid
// filesystem paths.  certData and keyData must not be empty.
func (db *CustomDomainDB) saveCertData(
	ctx context.Context,
	l *slog.Logger,
	certPath string,
	certData []byte,
	keyPath string,
	keyData []byte,
) (err error) {
	certsPEM, keyPEM, err := db.certDataToPEM(ctx, l, certData, keyData)
	if err != nil {
		return fmt.Errorf("encoding pem: %w", err)
	}

	_, err = tls.X509KeyPair(certsPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("parsing pair: %w", err)
	}

	err = renameio.WriteFile(certPath, certsPEM, 0o600)
	if err != nil {
		return fmt.Errorf("writing cert to fs: %w", err)
	}

	l.DebugContext(ctx, "saved cert file", "path", certPath)

	err = renameio.WriteFile(keyPath, keyPEM, 0o600)
	if err != nil {
		return fmt.Errorf("writing key to fs: %w", err)
	}

	l.DebugContext(ctx, "saved key file", "path", keyPath)

	err = db.manager.Add(ctx, certPath, keyPath, true)
	if err != nil {
		return fmt.Errorf("adding to manager: %w", err)
	}

	return nil
}

// certDataToPEM converts the certificate DER data, which may contain multiple
// certificates, and the key data into PEM.  l must not be nil.
func (db *CustomDomainDB) certDataToPEM(
	ctx context.Context,
	l *slog.Logger,
	certDER []byte,
	keyData []byte,
) (cert, key []byte, err error) {
	certs, err := x509.ParseCertificates(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing certificates: %w", err)
	}

	l.DebugContext(ctx, "got certs from der", "num", len(certs))

	certsPEMData := &bytes.Buffer{}
	for i, derCert := range certs {
		err = pem.Encode(certsPEMData, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derCert.Raw,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("encoding cert at index %d: %w", i, err)
		}
	}

	certsPEM := certsPEMData.Bytes()

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyData,
	})

	return certsPEM, keyPEM, nil
}

// needsRefresh returns true if the certificate data is already on the
// filesystem.  Errors are logged and reported to Sentry.
func (db *CustomDomainDB) needsRefresh(
	ctx context.Context,
	certName agd.CertificateName,
	certPath string,
	keyPath string,
) (ok bool) {
	var errs []error
	defer func() {
		if err := errors.Join(errs...); err != nil {
			err = fmt.Errorf("checking cert %q: %w", certName, err)
			errcoll.Collect(ctx, db.errColl, db.logger, "checking cert for refresh", err)
		}
	}()

	hasCert := false
	_, err := os.Stat(certPath)
	if err == nil {
		// The cert file is there; go on and check the key.
		hasCert = true
	} else if errors.Is(err, os.ErrNotExist) {
		return true
	} else {
		errs = append(errs, fmt.Errorf("checking cert file: %w", err))
	}

	_, err = os.Stat(keyPath)
	if err == nil {
		// Both are present; no need to refresh, unless an error has occurred
		// while checking the cert.
		return !hasCert
	} else if errors.Is(err, os.ErrNotExist) {
		return true
	} else {
		errs = append(errs, fmt.Errorf("checking key file: %w", err))
	}

	return true
}

// addRetry adds the certificate into the retry map.  retries must not be nil.
func (db *CustomDomainDB) addRetry(
	ctx context.Context,
	retries map[agd.CertificateName]*customDomainRetry,
	certName agd.CertificateName,
	now time.Time,
) {
	db.logger.DebugContext(ctx, "retrying later", "cert_name", certName)

	retry := retries[certName]
	if retry == nil {
		sched := agdtime.NewExponentialSchedule(db.initRetryIvl, db.maxRetryIvl, 2)
		retry = &customDomainRetry{
			sched: sched,
		}

		retries[certName] = retry
	}

	retry.next = now.Add(retry.sched.UntilNext(now))
}

// performRetries refreshes the certs that have failed previously.  All errors
// are reported to db.errColl and logged.
func (db *CustomDomainDB) performRetries(
	ctx context.Context,
	retries map[agd.CertificateName]*customDomainRetry,
	now time.Time,
) {
	var errs []error
	for certName, retry := range retries {
		if retry.next.After(now) {
			db.logger.Log(
				ctx,
				slogutil.LevelTrace,
				"not retrying yet",
				"cert_name", certName,
				"next_retry", retry.next,
			)

			continue
		}

		db.logger.DebugContext(ctx, "retrying", "cert_name", certName)

		needsRetry, err := db.refreshCert(ctx, certName)
		if err != nil {
			err = fmt.Errorf("retrying refreshing cert %q: %w", certName, err)
			errs = append(errs, err)
		} else {
			delete(retries, certName)
		}

		if needsRetry {
			db.addRetry(ctx, retries, certName, now)
		}
	}

	err := errors.Join(errs...)
	if err != nil {
		errcoll.Collect(ctx, db.errColl, db.logger, "retrying certs", err)
	}
}
