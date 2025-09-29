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
	//
	// If isCustom is true, the certificate's data should not be reported in
	// metrics.
	//
	// Add must ignore duplicates.
	Add(ctx context.Context, certPath, keyPath string, isCustom bool) (err error)

	// Clone returns the TLS configuration that contains saved TLS certificates.
	Clone() (c *tls.Config)

	// CloneWithMetrics is like [Manager.Clone] but it also sets metrics.
	CloneWithMetrics(proto, srvName string, deviceDomains []string) (c *tls.Config)

	// Remove deletes a certificate using the provided paths to its certificate
	// and key.  certPath and keyPath must not be empty.
	//
	// If isCustom is true, the certificate's data should not be reported in
	// metrics.
	Remove(ctx context.Context, certPath, keyPath string, isCustom bool) (err error)
}

// EmptyManager is the implementation of the [Manager] interface that does
// nothing.
type EmptyManager struct{}

// type check
var _ Manager = EmptyManager{}

// Add implements the [Manager] interface for EmptyManager.
func (EmptyManager) Add(_ context.Context, _, _ string, _ bool) (err error) { return nil }

// Clone implements the [Manager] interface for EmptyManager.
func (EmptyManager) Clone() (c *tls.Config) { return nil }

// CloneWithMetrics implements the [Manager] interface for EmptyManager.
func (EmptyManager) CloneWithMetrics(_, _ string, _ []string) (c *tls.Config) { return nil }

// Remove implements the [Manager] interface for EmptyManager.
func (EmptyManager) Remove(_ context.Context, _, _ string, _ bool) (err error) { return nil }

// DefaultManagerConfig is the configuration structure for [DefaultManager].
type DefaultManagerConfig struct {
	// Logger is used for logging the operation of the TLS manager.  It must not
	// be nil.
	Logger *slog.Logger

	// ErrColl is used to collect TLS-related errors.  It must not be nil.
	ErrColl errcoll.Interface

	// Metrics is used to collect TLS-related statistics.  It must not be nil.
	//
	// TODO(a.garipov):  See if the custom-domain certificates need any metrics.
	Metrics ManagerMetrics

	// TicketDB stores paths to the TLS session tickets and updates them.  It
	// must not be nil.
	TicketDB TicketDB

	// KeyLogFilename, if not empty, is the name of the TLS key log file.  If
	// not empty, KeyLogFilename must be a valid file path.
	KeyLogFilename string
}

// DefaultManager is the default implementation of [Manager].
type DefaultManager struct {
	// mu protects fields certStorage, clones, clonesWithMetrics,
	// sessTicketPaths.
	mu                *sync.Mutex
	logger            *slog.Logger
	errColl           errcoll.Interface
	metrics           ManagerMetrics
	tickDB            TicketDB
	idx               *certIndex
	original          *tls.Config
	clones            []*tls.Config
	clonesWithMetrics []*tls.Config
}

// NewDefaultManager returns a new initialized *DefaultManager.  c must not be
// nil and must be valid.
func NewDefaultManager(c *DefaultManagerConfig) (m *DefaultManager, err error) {
	var kl io.Writer
	fn := c.KeyLogFilename
	if fn != "" {
		kl, err = tlsKeyLogWriter(fn)
		if err != nil {
			return nil, fmt.Errorf("initializing tls key log writer: %w", err)
		}
	}

	m = &DefaultManager{
		mu:      &sync.Mutex{},
		logger:  c.Logger,
		errColl: c.ErrColl,
		metrics: c.Metrics,
		tickDB:  c.TicketDB,
		idx:     &certIndex{},
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
	isCustom bool,
) (err error) {
	cp := &certPaths{
		certPath: certPath,
		keyPath:  keyPath,
		isCustom: isCustom,
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.idx.contains(cp) {
		m.logger.InfoContext(
			ctx,
			"skipping already added certificate",
			"cert", cp.certPath,
			"key", cp.keyPath,
			"is_custom", cp.isCustom,
		)

		return nil
	}

	cert, err := m.load(ctx, cp)
	if err != nil {
		return fmt.Errorf("adding certificate: %w", err)
	}

	m.idx.add(cert, cp)

	m.logger.InfoContext(
		ctx,
		"added certificate",
		"cert", cp.certPath,
		"key", cp.keyPath,
		"is_custom", cp.isCustom,
	)

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

	if !cp.isCustom {
		authAlgo := cert.Leaf.PublicKeyAlgorithm.String()
		subj := cert.Leaf.Subject.String()
		m.metrics.SetCertificateInfo(ctx, authAlgo, subj, cert.Leaf.NotAfter)
	}

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

	if m.idx.count() == 0 {
		return nil, errors.Error("no certificates")
	}

	return m.idx.certFor(chi)
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
		m.idx.stored(),
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
			errcoll.Collect(ctx, m.errColl, m.logger, "certificate refresh failed", err)
		}
	}()

	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	m.idx.rangeFn(func(_ *tls.Certificate, cp *certPaths) (cont bool) {
		cert, loadErr := m.load(ctx, cp)
		if err != nil {
			errs = append(errs, loadErr)

			return true
		}

		msg, lvl := "refreshed certificate", slog.LevelInfo
		if !m.idx.update(cp, cert) {
			msg, lvl = "certificate did not refresh", slog.LevelWarn
		}

		m.logger.Log(ctx, lvl, msg, "cert", cp.certPath, "key", cp.keyPath)

		return true
	})

	err = errors.Join(errs...)
	if err != nil {
		return fmt.Errorf("refreshing tls certificates: %w", err)
	}

	m.logger.InfoContext(ctx, "refresh successful", "num_configs", m.idx.count())

	return nil
}

// Remove removes a certificate from the manager.  certPath and keyPath must not
// be empty.
func (m *DefaultManager) Remove(
	ctx context.Context,
	certPath string,
	keyPath string,
	isCustom bool,
) (err error) {
	cp := &certPaths{
		certPath: certPath,
		keyPath:  keyPath,
		isCustom: isCustom,
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.idx.remove(cp)

	m.logger.InfoContext(
		ctx,
		"removed certificate",
		"cert", cp.certPath,
		"key", cp.keyPath,
		"is_custom", cp.isCustom,
	)

	return nil
}

// RotateTickets refreshes and resets TLS session tickets.  It may be used as a
// [service.RefresherFunc].
func (m *DefaultManager) RotateTickets(ctx context.Context) (err error) {
	m.logger.DebugContext(ctx, "ticket rotation started")
	defer m.logger.DebugContext(ctx, "ticket rotation finished")

	paths, err := m.tickDB.Paths(ctx)
	if err != nil {
		errcoll.Collect(ctx, m.errColl, m.logger, "rotating tickets", err)
	}

	if len(paths) == 0 {
		return nil
	}

	defer func() {
		m.metrics.SetSessionTicketRotationStatus(ctx, err)

		if err != nil {
			errcoll.Collect(ctx, m.errColl, m.logger, "ticket rotation failed", err)
		}
	}()

	tickets := make([]SessionTicket, 0, len(paths))
	for _, filePath := range paths {
		var ticket SessionTicket
		ticket, err = readSessionTicketFile(filePath)
		if err != nil {
			return fmt.Errorf("reading session ticket: %w", err)
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
		"num_configs", m.idx.count(),
		"num_tickets", len(tickets),
		"num_clones", len(m.clones),
		"num_clones_with_metrics", len(m.clonesWithMetrics),
	)

	return nil
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
