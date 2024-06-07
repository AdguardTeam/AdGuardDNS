package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/service"
	"github.com/prometheus/client_golang/prometheus"
)

// TLS Configuration And Utilities

// tlsConfig are the TLS settings of a DNS server, if any.
type tlsConfig struct {
	// Certificates are TLS certificates for this server.
	Certificates tlsConfigCerts `yaml:"certificates"`

	// SessionKeys are paths to files containing the TLS session keys for this
	// server.
	SessionKeys []string `yaml:"session_keys"`

	// DeviceIDWildcards are the wildcard domains that are used to infer device
	// IDs from the clients' server names.
	//
	// TODO(a.garipov): Validate the actual DNS Names in the certificates
	// against these?
	DeviceIDWildcards []string `yaml:"device_id_wildcards"`
}

// toInternal converts c to the TLS configuration for a DNS server.  c is
// assumed to be valid.
func (c *tlsConfig) toInternal() (conf *agd.TLS, err error) {
	if c == nil {
		return nil, nil
	}

	tlsConf, err := c.Certificates.toInternal()
	if err != nil {
		return nil, fmt.Errorf("certificates: %w", err)
	}

	return &agd.TLS{
		Conf: tlsConf,
		// TODO(e.burkov):  Consider trimming the asterisk since the values are
		// only used in this way.
		DeviceIDWildcards: slices.Clone(c.DeviceIDWildcards),
		SessionKeys:       c.SessionKeys,
	}, nil
}

// validate returns an error if the TLS configuration is invalid for the given
// protocol.
func (c *tlsConfig) validate(needsTLS bool) (err error) {
	switch {
	case c == nil:
		if needsTLS {
			return errors.Error("server group requires tls")
		}

		// No TLS settings, which is normal.
		return nil
	case !needsTLS:
		return errors.Error("server group does not require tls")
	}

	if len(c.Certificates) == 0 {
		return errors.Error("no certificates")
	}

	err = c.Certificates.validate()
	if err != nil {
		return fmt.Errorf("certificates: %w", err)
	}

	err = validateDeviceIDWildcards(c.DeviceIDWildcards)
	if err != nil {
		return fmt.Errorf("device_id_wildcards: %w", err)
	}

	return nil
}

// validateDeviceIDWildcards returns an error if the device ID domain wildcards
// are invalid.
func validateDeviceIDWildcards(wildcards []string) (err error) {
	s := container.NewMapSet[string]()
	for i, w := range wildcards {
		// TODO(e.burkov):  Consider removing this requirement.
		if !strings.HasPrefix(w, "*.") {
			return fmt.Errorf("at index %d: not a wildcard", i)
		} else if s.Has(w) {
			return fmt.Errorf("at index %d: duplicated wildcard", i)
		}

		s.Add(w)
	}

	return nil
}

// tlsConfigCert is a single TLS certificate.
type tlsConfigCert struct {
	// Certificate is the path to the TLS certificate.
	Certificate string `yaml:"certificate"`

	// Key is the path to the TLS private key.
	Key string `yaml:"key"`
}

// tlsConfigCerts are TLS certificates.  A valid instance of tlsConfigCerts has
// no nil items.
type tlsConfigCerts []*tlsConfigCert

// toInternal converts certs to a TLS configuration.  certs are assumed to be
// valid.
func (certs tlsConfigCerts) toInternal() (conf *tls.Config, err error) {
	if len(certs) == 0 {
		return nil, nil
	}

	tlsCerts := make([]tls.Certificate, len(certs))
	for i, c := range certs {
		var cert tls.Certificate
		cert, err = tls.LoadX509KeyPair(c.Certificate, c.Key)
		if err != nil {
			return nil, fmt.Errorf("certificate at index %d: %w", i, err)
		}

		var leaf *x509.Certificate
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("invalid leaf, certificate at index %d: %w", i, err)
		}

		cert.Leaf = leaf
		tlsCerts[i] = cert

		authAlgo, subj := leaf.PublicKeyAlgorithm.String(), leaf.Subject.String()
		metrics.TLSCertificateInfo.With(prometheus.Labels{
			"auth_algo": authAlgo,
			"subject":   subj,
		}).Set(1)
		metrics.TLSCertificateNotAfter.With(prometheus.Labels{
			"subject": subj,
		}).Set(float64(leaf.NotAfter.Unix()))
	}

	return &tls.Config{
		Certificates: tlsCerts,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}, nil
}

// validate returns an error if the certificates are invalid.
func (certs tlsConfigCerts) validate() (err error) {
	for i, c := range certs {
		switch {
		case c == nil:
			return fmt.Errorf("at index %d: no certificate object", i)
		case c.Certificate == "":
			return fmt.Errorf("at index %d: no certificate", i)
		case c.Key == "":
			return fmt.Errorf("at index %d: no key", i)
		}
	}

	return nil
}

// TLS Session Ticket Key Rotator

// ticketRotator is a refresh worker that rereads and resets TLS session tickets.
type ticketRotator struct {
	errColl errcoll.Interface
	confs   map[*tls.Config][]string
}

// newTicketRotator creates a new TLS session ticket rotator that rotates
// tickets for the TLS configurations of all servers in grps.
//
// grps is assumed to be valid.
func newTicketRotator(
	errColl errcoll.Interface,
	grps []*agd.ServerGroup,
) (tr *ticketRotator, err error) {
	confs := map[*tls.Config][]string{}

	for _, g := range grps {
		t := g.TLS
		if t == nil || len(t.SessionKeys) == 0 {
			continue
		}

		for _, srv := range g.Servers {
			if srv.TLS != nil {
				confs[srv.TLS] = t.SessionKeys
			}
		}
	}

	tr = &ticketRotator{
		errColl: errColl,
		confs:   confs,
	}

	err = tr.Refresh(context.Background())
	if err != nil {
		return nil, fmt.Errorf("initial session ticket refresh: %w", err)
	}

	return tr, nil
}

// sessTickLen is the length of a single TLS session ticket key in bytes.
//
// NOTE: Unlike Nginx, Go's crypto/tls doesn't use the random bytes from the
// session ticket keys as-is, but instead hashes these bytes and uses the first
// 48 bytes of the hashed data as the key name, the AES key, and the HMAC key.
const sessTickLen = 32

// type check
var _ agdservice.Refresher = (*ticketRotator)(nil)

// Refresh implements the [agdservice.Refresher] interface for *ticketRotator.
func (r *ticketRotator) Refresh(ctx context.Context) (err error) {
	// TODO(a.garipov):  Use slog.
	log.Debug("tickrot_refresh: started")
	defer log.Debug("tickrot_refresh: finished")

	defer func() {
		if err != nil {
			errcoll.Collectf(ctx, r.errColl, "tickrot_refresh: %w", err)
		}
	}()

	for conf, files := range r.confs {
		keys := make([][sessTickLen]byte, 0, len(files))

		for _, fileName := range files {
			var key [sessTickLen]byte
			key, err = readSessionTicketKey(fileName)
			if err != nil {
				metrics.TLSSessionTicketsRotateStatus.Set(0)

				return fmt.Errorf("session ticket for srv %s: %w", conf.ServerName, err)
			}

			keys = append(keys, key)
		}

		if len(keys) == 0 {
			return fmt.Errorf("no session tickets for srv %s in %q", conf.ServerName, files)
		}

		conf.SetSessionTicketKeys(keys)
	}

	metrics.TLSSessionTicketsRotateStatus.Set(1)
	metrics.TLSSessionTicketsRotateTime.SetToCurrentTime()

	return nil
}

// readSessionTicketKey reads a single TLS session ticket key from a file.
func readSessionTicketKey(fn string) (key [sessTickLen]byte, err error) {
	// #nosec G304 -- Trust the file paths that are given to us in the
	// configuration file.
	b, err := os.ReadFile(fn)
	if err != nil {
		return key, fmt.Errorf("reading session ticket: %w", err)
	}

	if len(b) < sessTickLen {
		return key, fmt.Errorf("session ticket in %s: bad len %d, want %d", fn, len(b), sessTickLen)
	}

	return [sessTickLen]byte(b), nil
}

// enableTLSKeyLogging enables TLS key logging (use for debug purposes only).
func enableTLSKeyLogging(grps []*agd.ServerGroup, keyLogFileName string) (err error) {
	path := filepath.Clean(keyLogFileName)

	// TODO(a.garipov): Consider closing the file when we add SIGHUP support.
	kl, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("opening SSL_KEY_LOG_FILE: %w", err)
	}

	for _, g := range grps {
		for _, s := range g.Servers {
			if s.TLS != nil {
				s.TLS.KeyLogWriter = kl
			}
		}
	}

	return nil
}

// setupTicketRotator creates and returns a ticket rotator as well as starts and
// registers its refresher in the signal handler.
func setupTicketRotator(
	srvGrps []*agd.ServerGroup,
	sigHdlr *service.SignalHandler,
	errColl errcoll.Interface,
) (err error) {
	tickRot, err := newTicketRotator(errColl, srvGrps)
	if err != nil {
		return fmt.Errorf("setting up ticket rotator: %w", err)
	}

	refr := agdservice.NewRefreshWorker(&agdservice.RefreshWorkerConfig{
		Context:   ctxWithDefaultTimeout,
		Refresher: tickRot,
		Name:      "tickrot",
		// TODO(ameshkov): Consider making configurable.
		Interval:          1 * time.Minute,
		RefreshOnShutdown: false,
		RandomizeStart:    false,
	})
	err = refr.Start(context.Background())
	if err != nil {
		return fmt.Errorf("starting ticket rotator refresh: %w", err)
	}

	sigHdlr.Add(refr)

	return nil
}
