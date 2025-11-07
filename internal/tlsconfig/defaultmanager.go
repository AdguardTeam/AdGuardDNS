package tlsconfig

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/service"
)

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

	// KeyLogPath, if not empty, is the path to the TLS key log file.  If not
	// empty, KeyLogPath should be a valid file path.
	KeyLogPath string
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
	certStorage       *certIndex
	original          *tls.Config
	clones            []*tls.Config
	clonesWithMetrics []*tls.Config
}

// NewDefaultManager returns a new initialized *DefaultManager.  c must not be
// nil and must be valid.
func NewDefaultManager(c *DefaultManagerConfig) (m *DefaultManager, err error) {
	var keyLogWriter io.Writer

	if keyLogFilePath := c.KeyLogPath; keyLogFilePath != "" {
		keyLogWriter, err = tlsKeyLogWriter(keyLogFilePath)
		if err != nil {
			return nil, fmt.Errorf("initializing tls key log writer: %w", err)
		}
	}

	m = &DefaultManager{
		mu:          &sync.Mutex{},
		logger:      c.Logger,
		errColl:     c.ErrColl,
		metrics:     c.Metrics,
		tickDB:      c.TicketDB,
		certStorage: newCertIndex(),
	}

	m.original = &tls.Config{
		GetCertificate: m.getCertificate,
		MinVersion:     tls.VersionTLS12,
		MaxVersion:     tls.VersionTLS13,
		KeyLogWriter:   keyLogWriter,
	}

	return m, nil
}

// type check
var _ Manager = (*DefaultManager)(nil)

// Add implements the [Manager] interface for *DefaultManager.
func (m *DefaultManager) Add(ctx context.Context, params *AddParams) (err error) {
	l := m.logger.With(
		"cert", params.CertPath,
		"key", params.KeyPath,
		"is_custom", params.IsCustom,
	)

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.certStorage.contains(params.Name) {
		l.InfoContext(ctx, "skipping already added certificate")

		return nil
	}

	cert, err := m.load(ctx, params)
	if err != nil {
		return fmt.Errorf("adding certificate: %w", err)
	}

	m.certStorage.add(params.Name, &certData{
		cert:     cert,
		certPath: params.CertPath,
		keyPath:  params.KeyPath,
		isCustom: params.IsCustom,
	})

	l.InfoContext(ctx, "added certificate")

	return nil
}

// Bind implements the [Manager] interface for *DefaultManager.
func (m *DefaultManager) Bind(
	ctx context.Context,
	name agd.CertificateName,
	pref netip.Prefix,
) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	added := m.certStorage.bind(name, pref)
	if !added {
		m.logger.InfoContext(ctx, "skipping existing binding", "cert", name, "pref", pref)
	}

	return nil
}

// load returns a new TLS configuration from the provided certificate and key
// paths.  m.mu must be locked.  c must not be modified.
func (m *DefaultManager) load(ctx context.Context, p *AddParams) (c *tls.Certificate, err error) {
	cert, err := tls.LoadX509KeyPair(p.CertPath, p.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading certificate: %w", err)
	}

	if !p.IsCustom {
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
			errcoll.Collect(ctx, m.errColl, m.logger, "certificate refresh failed", err)
		}
	}()

	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	m.certStorage.rangeFn(func(name agd.CertificateName, cd *certData) (cont bool) {
		cert, loadErr := m.load(ctx, &AddParams{
			Name:     name,
			CertPath: cd.certPath,
			KeyPath:  cd.keyPath,
			IsCustom: cd.isCustom,
		})
		if loadErr != nil {
			errs = append(errs, loadErr)

			return true
		}

		msg, lvl := "refreshed certificate", slog.LevelInfo
		if !m.certStorage.update(name, cert) {
			msg, lvl = "certificate did not refresh", slog.LevelWarn
		}

		m.logger.Log(ctx, lvl, msg, "name", name, "cert", cd.certPath, "key", cd.keyPath)

		return true
	})

	err = errors.Join(errs...)
	if err != nil {
		return fmt.Errorf("refreshing tls certificates: %w", err)
	}

	m.logger.InfoContext(ctx, "refresh successful", "num_configs", m.certStorage.count())

	return nil
}

// Remove removes a certificate from the manager.  certPath and keyPath must not
// be empty.
func (m *DefaultManager) Remove(
	ctx context.Context,
	name agd.CertificateName,
) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.certStorage.remove(name)

	m.logger.InfoContext(
		ctx,
		"removed certificate",
		"name", name,
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
		"num_configs", m.certStorage.count(),
		"num_tickets", len(tickets),
		"num_clones", len(m.clones),
		"num_clones_with_metrics", len(m.clonesWithMetrics),
	)

	return nil
}

// readSessionTicketFile reads a single TLS session ticket from a file.
func readSessionTicketFile(filePath string) (ticket SessionTicket, err error) {
	// #nosec G304 -- Trust the file paths that are given to us in the
	// configuration file.
	b, err := os.ReadFile(filePath)
	if err != nil {
		return SessionTicket{}, fmt.Errorf("reading session ticket: %w", err)
	}

	ticket, err = NewSessionTicket(b)
	if err != nil {
		return SessionTicket{}, fmt.Errorf("session ticket in %q: %w", filePath, err)
	}

	return ticket, nil
}

// tlsKeyLogWriter returns a writer for logging TLS secrets to file at
// keyLogPath.
func tlsKeyLogWriter(keyLogPath string) (kl io.Writer, err error) {
	path := filepath.Clean(keyLogPath)

	// TODO(a.garipov): Consider closing the file when we add SIGHUP support.
	kl, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return kl, nil
}
