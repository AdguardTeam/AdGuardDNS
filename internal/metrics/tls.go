package metrics

import (
	"crypto/tls"
	"fmt"
	"slices"
	"strings"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// TLSCertificateInfo is a gauge with the authentication algorithm of
	// the certificate.
	TLSCertificateInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "cert_info",
		Namespace: namespace,
		Subsystem: subsystemTLS,
		Help:      "Authentication algorithm and other information about the certificate.",
	}, []string{"auth_algo", "subject"})

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
	devDomains []string,
	srvCerts []tls.Certificate,
) (f func(tls.ConnectionState) error) {
	return func(state tls.ConnectionState) error {
		sLabel := serverNameToLabel(state.ServerName, srvName, devDomains, srvCerts)

		// Stick to using WithLabelValues instead of With in order to avoid
		// extra allocations on prometheus.Labels.  The labels order is VERY
		// important here.
		TLSHandshakeTotal.WithLabelValues(
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

// TLSMetricsBeforeHandshake is a function that needs to be passed to
// *tls.Config GetConfigForClient.
func TLSMetricsBeforeHandshake(proto string) (f func(*tls.ClientHelloInfo) (*tls.Config, error)) {
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
		TLSHandshakeAttemptsTotal.WithLabelValues(
			proto,
			strings.Join(supProtos, ","),
			tlsVersionToString(maxVersion),
		).Inc()

		return nil, nil
	}
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
	srvCerts []tls.Certificate,
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
func matchServerNames(sni string, devDomains []string, srvCerts []tls.Certificate) (match string) {
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
	matchedDomain = ""
	for _, domain := range domains {
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
