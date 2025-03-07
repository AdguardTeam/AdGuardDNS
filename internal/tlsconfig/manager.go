package tlsconfig

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/service"
)

// Manager stores and updates TLS configurations.
type Manager interface {
	// Add saves an initialized TLS certificate using the provided paths to a
	// certificate and a key.  certPath and keyPath must not be empty.
	Add(ctx context.Context, certPath, keyPath string) (err error)

	// Clone returns the TLS configuration that contains saved TLS certificates.
	Clone() (c *tls.Config)

	// CloneWithMetrics is like [Manager.Clone] but it also sets metrics.
	CloneWithMetrics(proto, srvName string, deviceDomains []string) (c *tls.Config)
}

// DefaultManagerConfig is the configuration structure for [DefaultManager].
//
// TODO(s.chzhen):  Use it.
type DefaultManagerConfig struct {
	// Logger is used for logging the operation of the TLS manager.
	Logger *slog.Logger

	// ErrColl is used to collect TLS-related errors.
	ErrColl errcoll.Interface

	// Metrics is used to collect TLS-related statistics.
	Metrics Metrics

	// KeyLogFilename, if not empty, is the name of the TLS key log file.
	KeyLogFilename string

	// SessionTicketPaths are paths to files containing the TLS session tickets.
	SessionTicketPaths []string
}

// DefaultManager is the default implementation of [Manager].
type DefaultManager struct {
	// mu protects fields certStorage, clones, clonesWithMetrics,
	// sessTicketPaths.
	mu                *sync.Mutex
	logger            *slog.Logger
	errColl           errcoll.Interface
	metrics           Metrics
	certStorage       *certStorage
	original          *tls.Config
	clones            []*tls.Config
	clonesWithMetrics []*tls.Config
	sessTicketPaths   []string
}

// NewDefaultManager returns a new initialized *DefaultManager.
func NewDefaultManager(conf *DefaultManagerConfig) (m *DefaultManager, err error) {
	var kl io.Writer
	fn := conf.KeyLogFilename
	if fn != "" {
		kl, err = tlsKeyLogWriter(fn)
		if err != nil {
			return nil, fmt.Errorf("initializing tls key log writer: %w", err)
		}
	}

	m = &DefaultManager{
		mu:              &sync.Mutex{},
		logger:          conf.Logger,
		errColl:         conf.ErrColl,
		metrics:         conf.Metrics,
		certStorage:     &certStorage{},
		sessTicketPaths: conf.SessionTicketPaths,
	}

	m.original = &tls.Config{
		GetCertificate: m.getCertificate,
		MinVersion:     tls.VersionTLS12,
		MaxVersion:     tls.VersionTLS13,
		KeyLogWriter:   kl,
	}

	return m, nil
}

// type check
var _ Manager = (*DefaultManager)(nil)

// Add implements the [Manager] interface for *DefaultManager.
func (m *DefaultManager) Add(
	ctx context.Context,
	certPath string,
	keyPath string,
) (err error) {
	cp := &certPaths{
		certPath: certPath,
		keyPath:  keyPath,
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.certStorage.contains(cp) {
		m.logger.InfoContext(
			ctx,
			"skipping already added certificate",
			"cert", cp.certPath,
			"key", cp.keyPath,
		)

		return nil
	}

	cert, err := m.load(ctx, cp)
	if err != nil {
		return fmt.Errorf("adding certificate: %w", err)
	}

	m.certStorage.add(cert, cp)

	m.logger.InfoContext(ctx, "added certificate", "cert", cp.certPath, "key", cp.keyPath)

	return nil
}

// load returns a new TLS configuration from the provided certificate and key
// paths.  m.mu must be locked.  c must not be modified.
func (m *DefaultManager) load(
	ctx context.Context,
	cp *certPaths,
) (c *tls.Certificate, err error) {
	cert, err := tls.LoadX509KeyPair(cp.certPath, cp.keyPath)
	if err != nil {
		return nil, fmt.Errorf("loading certificate: %w", err)
	}

	authAlgo := cert.Leaf.PublicKeyAlgorithm.String()
	subj := cert.Leaf.Subject.String()
	m.metrics.SetCertificateInfo(ctx, authAlgo, subj, cert.Leaf.NotAfter)

	return &cert, nil
}

// Clone implements the [Manager] interface for *DefaultManager.
func (m *DefaultManager) Clone() (clone *tls.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()

	clone = m.original.Clone()
	m.clones = append(m.clones, clone)

	return clone
}

// getCertificate returns the TLS certificate for chi.  See
// [tls.Config.GetCertificate].  c must not be modified.
func (m *DefaultManager) getCertificate(chi *tls.ClientHelloInfo) (c *tls.Certificate, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.certStorage.count() == 0 {
		return nil, errors.Error("no certificates")
	}

	return m.certStorage.certFor(chi)
}

// CloneWithMetrics implements the [Manager] interface for *DefaultManager.
func (m *DefaultManager) CloneWithMetrics(
	proto string,
	srvName string,
	deviceDomains []string,
) (conf *tls.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()

	clone := m.original.Clone()

	clone.GetConfigForClient = m.metrics.BeforeHandshake(proto)

	clone.GetCertificate = m.getCertificate

	clone.VerifyConnection = m.metrics.AfterHandshake(
		proto,
		srvName,
		deviceDomains,
		m.certStorage.stored(),
	)

	m.clonesWithMetrics = append(m.clonesWithMetrics, clone)

	return clone
}

// type check
var _ service.Refresher = (*DefaultManager)(nil)

// Refresh implements the [service.Refresher] interface for *DefaultManager.
func (m *DefaultManager) Refresh(ctx context.Context) (err error) {
	m.logger.DebugContext(ctx, "refresh started")
	defer m.logger.DebugContext(ctx, "refresh finished")

	defer func() {
		if err != nil {
			errcoll.Collect(ctx, m.errColl, m.logger, "cerificate refresh failed", err)
		}
	}()

	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	m.certStorage.rangeFn(func(_ *tls.Certificate, cp *certPaths) (cont bool) {
		cert, loadErr := m.load(ctx, cp)
		if err != nil {
			errs = append(errs, loadErr)

			return true
		}

		msg, lvl := "refreshed certificate", slog.LevelInfo
		if !m.certStorage.update(cp, cert) {
			msg, lvl = "certificate did not refresh", slog.LevelWarn
		}

		m.logger.Log(ctx, lvl, msg, "cert", cp.certPath, "key", cp.keyPath)

		return true
	})

	err = errors.Join(errs...)
	if err != nil {
		return fmt.Errorf("refreshing tls certificates: %w", err)
	}

	m.logger.InfoContext(ctx, "refresh successful", "num_configs", m.certStorage.count())

	return nil
}

// sessTickLen is the length of a single TLS session ticket key in bytes.
//
// NOTE: Unlike Nginx, Go's crypto/tls doesn't use the random bytes from the
// session ticket keys as-is, but instead hashes these bytes and uses the first
// 48 bytes of the hashed data as the key name, the AES key, and the HMAC key.
const sessTickLen = 32

// sessionTicket is a type alias for a single TLS session ticket.
type sessionTicket = [sessTickLen]byte

// RotateTickets rereads and resets TLS session tickets.
func (m *DefaultManager) RotateTickets(ctx context.Context) (err error) {
	m.logger.DebugContext(ctx, "ticket rotation started")
	defer m.logger.DebugContext(ctx, "ticket rotation finished")

	files := m.sessTicketPaths
	if len(files) == 0 {
		return nil
	}

	defer func() {
		m.metrics.SetSessionTicketRotationStatus(ctx, err)

		if err != nil {
			errcoll.Collect(ctx, m.errColl, m.logger, "ticket rotation failed", err)
		}
	}()

	tickets := make([]sessionTicket, 0, len(files))
	for _, fileName := range files {
		var ticket sessionTicket
		ticket, err = readSessionTicketKey(fileName)
		if err != nil {
			return fmt.Errorf("reading sesion ticket: %w", err)
		}

		tickets = append(tickets, ticket)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, conf := range m.clones {
		conf.SetSessionTicketKeys(tickets)
	}

	for _, conf := range m.clonesWithMetrics {
		conf.SetSessionTicketKeys(tickets)
	}

	m.logger.InfoContext(
		ctx,
		"ticket rotation successful",
		"num_configs", m.certStorage.count(),
		"num_tickets", len(tickets),
	)

	return nil
}

// readSessionTicketKey reads a single TLS session ticket from a file.
func readSessionTicketKey(fn string) (ticket sessionTicket, err error) {
	// #nosec G304 -- Trust the file paths that are given to us in the
	// configuration file.
	b, err := os.ReadFile(fn)
	if err != nil {
		return ticket, fmt.Errorf("reading session ticket: %w", err)
	}

	tickLen := len(b)
	if tickLen < sessTickLen {
		return ticket, fmt.Errorf(
			"session ticket in %q: bad len %d, want no less than %d",
			fn,
			tickLen,
			sessTickLen,
		)
	}

	return sessionTicket(b), nil
}

// tlsKeyLogWriter returns a writer for logging TLS secrets to keyLogFilename.
func tlsKeyLogWriter(keyLogFilename string) (kl io.Writer, err error) {
	path := filepath.Clean(keyLogFilename)

	// TODO(a.garipov): Consider closing the file when we add SIGHUP support.
	kl, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return kl, nil
}
