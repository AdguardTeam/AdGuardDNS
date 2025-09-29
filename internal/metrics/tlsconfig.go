package metrics

import (
	"context"
	"crypto/tls"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/prometheus/client_golang/prometheus"
)

// TLSConfigManager is the Prometheus-based implementation of the
// [tlsconfig.ManagerMetrics] interface.
type TLSConfigManager struct {
	// certificateInfo is a gauge with the authentication algorithm of the
	// certificate.
	certificateInfo *prometheus.GaugeVec

	// certificateNotAfter is a gauge with the time when the certificate
	// expires.
	certificateNotAfter *prometheus.GaugeVec

	// sessionTicketsRotateStatus is a gauge with the status of the last tickets
	// rotation.
	sessionTicketsRotateStatus prometheus.Gauge

	// sessionTicketsRotateTime is a gauge with the time when the TLS session
	// tickets were rotated.
	sessionTicketsRotateTime prometheus.Gauge

	// handshakeAttemptsTotal is a counter with the total number of attempts to
	// establish a TLS connection.  "supported_protos" is a comma-separated list
	// of the protocols supported by the client.
	handshakeAttemptsTotal *prometheus.CounterVec

	// handshakeTotal is a counter with the total count of TLS handshakes.
	handshakeTotal *prometheus.CounterVec
}

// NewTLSConfigManager registers the TLS-related metrics in reg and returns a
// properly initialized [*TLSConfigManager].
func NewTLSConfigManager(
	namespace string,
	reg prometheus.Registerer,
) (m *TLSConfigManager, err error) {
	const (
		certInfo                = "cert_info"
		certNotAfter            = "cert_not_after"
		sessTicketsRotateStatus = "session_tickets_rotate_status"
		sessTicketsRotateTime   = "session_tickets_rotate_time"
		handshakeAttemptsTotal  = "handshake_attempts_total"
		handshakeTotal          = "handshake_total"
	)

	m = &TLSConfigManager{
		certificateInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      certInfo,
			Namespace: namespace,
			Subsystem: subsystemTLS,
			Help:      "Authentication algorithm and other information about the certificate.",
		}, []string{"auth_algo", "subject"}),
		certificateNotAfter: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:      certNotAfter,
			Namespace: namespace,
			Subsystem: subsystemTLS,
			Help:      "Time when the certificate expires.",
		}, []string{"subject"}),
		sessionTicketsRotateStatus: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      sessTicketsRotateStatus,
			Namespace: namespace,
			Subsystem: subsystemTLS,
			Help:      "Status of the last tickets rotation.",
		}),
		sessionTicketsRotateTime: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      sessTicketsRotateTime,
			Namespace: namespace,
			Subsystem: subsystemTLS,
			Help:      "Time when the TLS session tickets were rotated.",
		}),
		handshakeAttemptsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      handshakeAttemptsTotal,
			Namespace: namespace,
			Subsystem: subsystemTLS,
			Help:      "Total count of TLS handshakes.",
		}, []string{
			"proto",
			"supported_protos",
			"tls_version",
		}),
		handshakeTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:      handshakeTotal,
			Namespace: namespace,
			Subsystem: subsystemTLS,
			Help:      "Total count of TLS handshakes.",
		}, []string{
			"proto",
			"tls_version",
			"did_resume",
			"cipher_suite",
			"negotiated_proto",
			"server_name",
		}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   certInfo,
		Value: m.certificateInfo,
	}, {
		Key:   certNotAfter,
		Value: m.certificateNotAfter,
	}, {
		Key:   sessTicketsRotateStatus,
		Value: m.sessionTicketsRotateStatus,
	}, {
		Key:   sessTicketsRotateTime,
		Value: m.sessionTicketsRotateTime,
	}, {
		Key:   handshakeAttemptsTotal,
		Value: m.handshakeAttemptsTotal,
	}, {
		Key:   handshakeTotal,
		Value: m.handshakeTotal,
	}}

	for _, c := range collectors {
		err = reg.Register(c.Value)
		if err != nil {
			errs = append(errs, fmt.Errorf("registering metrics %q: %w", c.Key, err))
		}
	}

	if err = errors.Join(errs...); err != nil {
		return nil, err
	}

	return m, nil
}

// BeforeHandshake implements the [tlsconfig.ManagerMetrics] interface for
// *TLSConfigManager.
func (m *TLSConfigManager) BeforeHandshake(
	proto string,
) (f func(*tls.ClientHelloInfo) (*tls.Config, error)) {
	return func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		var maxVersion uint16
		if len(info.SupportedVersions) > 0 {
			maxVersion = slices.Max(info.SupportedVersions)
		}

		supProtos := make([]string, len(info.SupportedProtos))
		for i := range info.SupportedProtos {
			supProtos[i] = strings.ToValidUTF8(info.SupportedProtos[i], "")
		}

		// Stick to using WithLabelValues instead of With in order to avoid
		// extra allocations on prometheus.Labels.  The labels order is VERY
		// important here.
		m.handshakeAttemptsTotal.WithLabelValues(
			proto,
			strings.Join(supProtos, ","),
			tlsVersionToString(maxVersion),
		).Inc()

		return nil, nil
	}
}

// AfterHandshake implements the [tlsconfig.ManagerMetrics] interface for
// *TLSConfigManager.
func (m *TLSConfigManager) AfterHandshake(
	proto string,
	srvName string,
	devDomains []string,
	srvCerts []*tls.Certificate,
) (f func(tls.ConnectionState) error) {
	return func(state tls.ConnectionState) error {
		sLabel := serverNameToLabel(state.ServerName, srvName, devDomains, srvCerts)

		// Stick to using WithLabelValues instead of With in order to avoid
		// extra allocations on prometheus.Labels.  The labels order is VERY
		// important here.
		m.handshakeTotal.WithLabelValues(
			proto,
			tlsVersionToString(state.Version),
			BoolString(state.DidResume),
			tls.CipherSuiteName(state.CipherSuite),
			// Don't validate the negotiated protocol since it's expected to
			// contain only ASCII after negotiation itself.
			state.NegotiatedProtocol,
			sLabel,
		).Inc()

		return nil
	}
}

// SetCertificateInfo implements the [tlsconfig.ManagerMetrics] interface for
// *TLSConfigManager.
func (m *TLSConfigManager) SetCertificateInfo(
	_ context.Context,
	algo string,
	subj string,
	notAfter time.Time,
) {
	m.certificateInfo.With(prometheus.Labels{
		"auth_algo": algo,
		"subject":   subj,
	}).Set(1)

	m.certificateNotAfter.With(prometheus.Labels{
		"subject": subj,
	}).Set(float64(notAfter.Unix()))
}

// SetSessionTicketRotationStatus implements the [tlsconfig.ManagerMetrics]
// interface for *TLSConfigManager.
func (m *TLSConfigManager) SetSessionTicketRotationStatus(_ context.Context, err error) {
	if err != nil {
		m.sessionTicketsRotateStatus.Set(0)

		return
	}

	m.sessionTicketsRotateStatus.Set(1)
	m.sessionTicketsRotateTime.SetToCurrentTime()
}

// tlsVersionToString converts TLS version to string.
func tlsVersionToString(ver uint16) (tlsVersion string) {
	switch ver {
	case tls.VersionTLS13:
		tlsVersion = "tls1.3"
	case tls.VersionTLS12:
		tlsVersion = "tls1.2"
	case tls.VersionTLS11:
		tlsVersion = "tls1.1"
	case tls.VersionTLS10:
		tlsVersion = "tls1.0"
	default:
		tlsVersion = "unknown"
	}

	return tlsVersion
}

// serverNameToLabel creates a metrics label from server name indication.  As
// it's necessary to keep labels set finite, all indications will be grouped.
func serverNameToLabel(
	sni string,
	srvName string,
	devDomains []string,
	srvCerts []*tls.Certificate,
) (label string) {
	if sni == "" {
		// SNI is empty, so the request is probably made on the IP address.
		return fmt.Sprintf("%s: other", srvName)
	}

	if matched := matchServerNames(sni, devDomains, srvCerts); matched != "" {
		return fmt.Sprintf("%s: %s", srvName, matched)
	}

	return fmt.Sprintf("%s: other", srvName)
}

// matchServerNames matches sni with known servers.
func matchServerNames(sni string, devDomains []string, srvCerts []*tls.Certificate) (match string) {
	if matchedDomain := matchDeviceDomains(sni, devDomains); matchedDomain != "" {
		return matchedDomain
	}

	if matched := matchSrvCerts(sni, srvCerts); matched != "" {
		return matched
	}

	return ""
}

// matchDeviceDomains matches sni to device domains.
func matchDeviceDomains(sni string, domains []string) (matchedDomain string) {
	for _, domain := range domains {
		if netutil.IsImmediateSubdomain(sni, domain) {
			return domain
		}
	}

	return ""
}

// matchSrvCerts matches sni to DNSNames in srvCerts.
func matchSrvCerts(sni string, srvCerts []*tls.Certificate) (match string) {
	for _, cert := range srvCerts {
		leaf := cert.Leaf
		if leaf == nil {
			continue
		}

		if match = matchSNI(sni, leaf.DNSNames); match != "" {
			return match
		}
	}

	return ""
}

// matchSNI finds match for sni in dnsNames.
func matchSNI(sni string, dnsNames []string) (match string) {
	for _, n := range dnsNames {
		if n == sni {
			return sni
		}

		if strings.HasPrefix(n, "*.") && netutil.IsImmediateSubdomain(sni, n[len("*."):]) {
			return n
		}
	}

	return ""
}

// CustomDomainDB is the Prometheus-based implementation of the
// [tlsconfig.CustomDomainDBMetrics] interface.
type CustomDomainDB struct {
	addCertDurationSeconds prometheus.Histogram
	matchDurationSeconds   prometheus.Histogram

	currentCustomDomainsCount prometheus.Gauge
	wellKnownPathsCount       prometheus.Gauge
}

// NewCustomDomainDB registers the custom-domain database metrics in reg and
// returns a properly initialized [*CustomDomainDB].
func NewCustomDomainDB(namespace string, reg prometheus.Registerer) (m *CustomDomainDB, err error) {
	const (
		addCertDurationSeconds = "custom_domains_add_cert_duration_seconds"
		matchDurationSeconds   = "custom_domains_match_duration_seconds"

		currentCustomDomainsCount = "custom_domains_current_count"
		wellKnownPathsCount       = "custom_domains_well_known_paths_count"
	)

	m = &CustomDomainDB{
		addCertDurationSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:      addCertDurationSeconds,
			Namespace: namespace,
			Subsystem: subsystemTLS,
			Help:      "The duration of adding a certificate to the database, in seconds.",
			Buckets:   []float64{0.000_1, 0.001, 0.01, 0.1},
		}),

		matchDurationSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:      matchDurationSeconds,
			Namespace: namespace,
			Subsystem: subsystemTLS,
			Help: "The duration of matching a client server name with " +
				"a custom domain name, in seconds",
			Buckets: []float64{0.000_001, 0.000_01, 0.000_1, 0.001},
		}),

		currentCustomDomainsCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      currentCustomDomainsCount,
			Namespace: namespace,
			Subsystem: subsystemTLS,
			Help:      "The number of current custom domains.",
		}),

		wellKnownPathsCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:      wellKnownPathsCount,
			Namespace: namespace,
			Subsystem: subsystemTLS,
			Help:      "The number of well-known paths for certificate validation.",
		}),
	}

	var errs []error
	collectors := container.KeyValues[string, prometheus.Collector]{{
		Key:   addCertDurationSeconds,
		Value: m.addCertDurationSeconds,
	}, {
		Key:   matchDurationSeconds,
		Value: m.matchDurationSeconds,
	}, {
		Key:   currentCustomDomainsCount,
		Value: m.currentCustomDomainsCount,
	}, {
		Key:   wellKnownPathsCount,
		Value: m.wellKnownPathsCount,
	}}

	for _, c := range collectors {
		err = reg.Register(c.Value)
		if err != nil {
			errs = append(errs, fmt.Errorf("registering metrics %q: %w", c.Key, err))
		}
	}

	if err = errors.Join(errs...); err != nil {
		return nil, err
	}

	return m, nil
}

// Operations for [*CustomDomainDB].  Keep in sync with
// [tlsconfig.CustomDomainDBMetricsOpAddCertificate] etc.
const (
	CustomDomainDBOpAddCertificate = "add_certificate"
	CustomDomainDBOpMatch          = "match"
)

// ObserveOperation implements the [CustomDomainDB] interface for
// CustomDomainDB.
func (m *CustomDomainDB) ObserveOperation(_ context.Context, op string, dur time.Duration) {
	switch op {
	case CustomDomainDBOpAddCertificate:
		m.addCertDurationSeconds.Observe(dur.Seconds())
	case CustomDomainDBOpMatch:
		m.matchDurationSeconds.Observe(dur.Seconds())
	default:
		panic(fmt.Errorf("op: %w: %q", errors.ErrBadEnumValue, op))
	}
}

// SetCurrentCustomDomainsCount implements the [CustomDomainDB] interface
// for CustomDomainDB.
func (m *CustomDomainDB) SetCurrentCustomDomainsCount(_ context.Context, n uint) {
	m.currentCustomDomainsCount.Set(float64(n))
}

// SetWellKnownPathsCount implements the [CustomDomainDB] interface
// for CustomDomainDB.
func (m *CustomDomainDB) SetWellKnownPathsCount(_ context.Context, n uint) {
	m.wellKnownPathsCount.Set(float64(n))
}
