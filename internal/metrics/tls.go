package metrics

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// TLSCertificateNotAfter is a gauge with the time when the certificate
	// expires.
	TLSCertificateNotAfter = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "cert_not_after",
		Namespace: namespace,
		Subsystem: subsystemTLS,
		Help:      "Time when the certificate expires.",
	}, []string{"subject"})

	// TLSSessionTicketsRotateStatus is a gauge with the status of the last
	// tickets rotation.
	TLSSessionTicketsRotateStatus = promauto.NewGauge(prometheus.GaugeOpts{
		Name:      "session_tickets_rotate_status",
		Namespace: namespace,
		Subsystem: subsystemTLS,
		Help:      "Status of the last tickets rotation.",
	})
	// TLSSessionTicketsRotateTime is a gauge with the time when the TLS session
	// tickets were rotated.
	TLSSessionTicketsRotateTime = promauto.NewGauge(prometheus.GaugeOpts{
		Name:      "session_tickets_rotate_time",
		Namespace: namespace,
		Subsystem: subsystemTLS,
		Help:      "Time when the TLS session tickets were rotated.",
	})
	// TLSHandshakeAttemptsTotal is a counter with the total number of attempts
	// to establish a TLS connection.  "supported_protos" is a comma-separated
	// list of the protocols supported by the client.
	TLSHandshakeAttemptsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "handshake_attempts_total",
		Namespace: namespace,
		Subsystem: subsystemTLS,
		Help:      "Total count of TLS handshakes.",
	}, []string{
		"proto",
		"supported_protos",
		"tls_version",
	})
	// TLSHandshakeTotal is a counter with the total count of TLS handshakes.
	TLSHandshakeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "handshake_total",
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
	})
)

// TLSMetricsAfterHandshake is a function that needs to be passed to
// *tls.Config VerifyConnection.
func TLSMetricsAfterHandshake(
	proto string,
	srvName string,
	wildcards []string,
	srvCerts []tls.Certificate,
) (f func(tls.ConnectionState) error) {
	return func(state tls.ConnectionState) error {
		sLabel := serverNameToLabel(state.ServerName, srvName, wildcards, srvCerts)
		TLSHandshakeTotal.With(prometheus.Labels{
			"proto":            proto,
			"tls_version":      tlsVersionToString(state.Version),
			"did_resume":       BoolString(state.DidResume),
			"cipher_suite":     tls.CipherSuiteName(state.CipherSuite),
			"negotiated_proto": state.NegotiatedProtocol,
			"server_name":      sLabel,
		}).Inc()

		return nil
	}
}

// TLSMetricsBeforeHandshake is a function that needs to be passed to
// *tls.Config GetConfigForClient.
func TLSMetricsBeforeHandshake(proto string) (f func(*tls.ClientHelloInfo) (*tls.Config, error)) {
	return func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		var maxVersion uint16
		for _, v := range info.SupportedVersions {
			if v > maxVersion {
				maxVersion = v
			}
		}

		TLSHandshakeAttemptsTotal.With(prometheus.Labels{
			"proto":            proto,
			"supported_protos": strings.Join(info.SupportedProtos, ","),
			"tls_version":      tlsVersionToString(maxVersion),
		}).Inc()

		return nil, nil
	}
}

// tlsVersionToString converts TLS version to string.
func tlsVersionToString(ver uint16) (tlsVersion string) {
	tlsVersion = "unknown"
	switch ver {
	case tls.VersionTLS13:
		tlsVersion = "tls1.3"
	case tls.VersionTLS12:
		tlsVersion = "tls1.2"
	case tls.VersionTLS11:
		tlsVersion = "tls1.1"
	case tls.VersionTLS10:
		tlsVersion = "tls1.0"
	}
	return tlsVersion
}

// serverNameToLabel creates a metrics label from server name indication.
// As it's necessary to keep labels set finite, all indications will be
// grouped.
func serverNameToLabel(
	sni string,
	srvName string,
	wildcards []string,
	srvCerts []tls.Certificate,
) (label string) {
	if sni == "" {
		// SNI is not provided, so the request is probably made on the
		// IP address.
		return fmt.Sprintf("%s: other", srvName)
	}

	if matched := matchServerNames(sni, wildcards, srvCerts); matched != "" {
		return fmt.Sprintf("%s: %s", srvName, matched)
	}

	return fmt.Sprintf("%s: other", srvName)
}

// matchServerNames matches sni with known servers.
func matchServerNames(sni string, wildcards []string, srvCerts []tls.Certificate) (match string) {
	if matchedDomain := matchDeviceIDWildcards(sni, wildcards); matchedDomain != "" {
		return matchedDomain
	}

	if matched := matchSrvCerts(sni, srvCerts); matched != "" {
		return matched
	}

	return ""
}

// matchDeviceIDWildcards matches sni to deviceID wildcards.
func matchDeviceIDWildcards(sni string, wildcards []string) (matchedDomain string) {
	matchedDomain = ""
	for _, wildcard := range wildcards {
		// Assume that wildcards have been validated for this prefix in the
		// configuration parsing.
		domain := wildcard[len("*."):]
		if netutil.IsImmediateSubdomain(sni, domain) {
			matchedDomain = domain

			break
		}
	}

	return matchedDomain
}

// matchSrvCerts matches sni to DNSNames in srvCerts.
func matchSrvCerts(sni string, srvCerts []tls.Certificate) (match string) {
	for _, cert := range srvCerts {
		leaf := cert.Leaf
		if leaf == nil {
			continue
		}

		for _, n := range leaf.DNSNames {
			if n == sni {
				return sni
			}

			if strings.HasPrefix(n, "*.") && netutil.IsImmediateSubdomain(sni, n[len("*."):]) {
				return n
			}
		}
	}

	return ""
}
