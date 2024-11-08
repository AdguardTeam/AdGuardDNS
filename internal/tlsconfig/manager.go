package tlsconfig

import (
	"cmp"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
)

// Manager stores and updates TLS configurations.
type Manager interface {
	// Add returns an initialized TLS configuration using the provided paths to
	// a certificate and a key.  certPath and keyPath must not be empty.
	Add(ctx context.Context, certPath, keyPath string) (c *tls.Config, err error)
}

// DefaultManagerConfig is the configuration structure for [DefaultManager].
//
// TODO(s.chzhen):  Use it.
type DefaultManagerConfig struct {
	// Logger is used for logging the operation of the TLS manager.
	Logger *slog.Logger

	// ErrColl is used to collect TLS related errors.
	ErrColl errcoll.Interface

	// Metrics is used to collect TLS related statistics.
	Metrics RefreshMetrics

	// KeyLogFilename, if not empty, is the name of the TLS key log file.
	KeyLogFilename string

	// SessionTicketPaths are paths to files containing the TLS session tickets.
	SessionTicketPaths []string
}

// certWithKey contains a certificate path and a key path.
type certWithKey struct {
	certPath string
	keyPath  string
}

// compare is a comparison function for the certWithKey.  It returns -1 if a
// sorts before b, 1 if a sorts after b, and 0 if their relative sorting
// position is the same.  The sorting prioritizes certificate paths first, and
// then key paths.
func (a certWithKey) compare(b certWithKey) (r int) {
	return cmp.Or(
		strings.Compare(a.certPath, b.certPath),
		strings.Compare(a.keyPath, b.keyPath),
	)
}

// DefaultManager is the default implementation of [Manager].
type DefaultManager struct {
	// mu prtotects configs, sessionTickets.
	mu              *sync.Mutex
	logger          *slog.Logger
	errColl         errcoll.Interface
	metrics         RefreshMetrics
	keyLogWriter    io.Writer
	configs         map[certWithKey]*tls.Config
	sessTicketPaths []string
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

	return &DefaultManager{
		mu:              &sync.Mutex{},
		logger:          conf.Logger,
		errColl:         conf.ErrColl,
		metrics:         conf.Metrics,
		keyLogWriter:    kl,
		configs:         make(map[certWithKey]*tls.Config),
		sessTicketPaths: conf.SessionTicketPaths,
	}, nil
}

// type check
var _ Manager = (*DefaultManager)(nil)

// Add implements the [Manager] interface for *DefaultManager.
func (m *DefaultManager) Add(
	ctx context.Context,
	certPath string,
	keyPath string,
) (conf *tls.Config, err error) {
	ck := certWithKey{
		certPath: certPath,
		keyPath:  keyPath,
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if conf = m.configs[ck]; conf != nil {
		return conf, nil
	}

	return m.add(ctx, ck)
}

// add returns a new TLS configuration from the provided certificate and key
// paths.  m.mu must be locked.
func (m *DefaultManager) add(ctx context.Context, ck certWithKey) (conf *tls.Config, err error) {
	cert, err := tls.LoadX509KeyPair(ck.certPath, ck.keyPath)
	if err != nil {
		return nil, fmt.Errorf("loading certificate: %w", err)
	}

	authAlgo := cert.Leaf.PublicKeyAlgorithm.String()
	subj := cert.Leaf.Subject.String()
	m.metrics.SetCertificateInfo(ctx, authAlgo, subj, cert.Leaf.NotAfter)

	if conf = m.configs[ck]; conf != nil {
		conf.GetCertificate = func(h *tls.ClientHelloInfo) (c *tls.Certificate, err error) {
			return &cert, nil
		}

		m.logger.InfoContext(ctx, "refreshed config", "cert", ck.certPath, "key", ck.keyPath)

		return conf, nil
	}

	conf = &tls.Config{
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (c *tls.Certificate, err error) {
			return &cert, nil
		},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		KeyLogWriter: m.keyLogWriter,
	}

	m.configs[ck] = conf

	m.logger.InfoContext(ctx, "added config", "cert", ck.certPath, "key", ck.keyPath)

	return conf, nil
}

// type check
var _ agdservice.Refresher = (*DefaultManager)(nil)

// Refresh implements the [agdservice.Refresher] interface for *DefaultManager.
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
	for _, ck := range slices.SortedFunc(maps.Keys(m.configs), certWithKey.compare) {
		_, err = m.add(ctx, ck)
		errs = append(errs, err)
	}

	err = errors.Join(errs...)
	if err != nil {
		return fmt.Errorf("refreshing tls certificates: %w", err)
	}

	m.logger.InfoContext(ctx, "refresh successful", "num_configs", len(m.configs))

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
		if err != nil {
			m.metrics.SetSessionTicketRotationStatus(ctx, false)
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

	for _, conf := range m.configs {
		conf.SetSessionTicketKeys(tickets)
	}

	m.logger.InfoContext(
		ctx,
		"ticket rotation successful",
		"num_configs", len(m.configs),
		"num_tickets", len(tickets),
	)

	m.metrics.SetSessionTicketRotationStatus(ctx, true)

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
	if tickLen != sessTickLen {
		return ticket, fmt.Errorf(
			"session ticket in %s: bad len %d, want %d",
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
