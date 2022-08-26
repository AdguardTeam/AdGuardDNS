package metrics_test

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLSMetricsAfterHandshake(t *testing.T) {
	serverName := "test_server"
	wildcards := []string{"*.d.adguard-dns.com"}
	dnsNames := []string{
		"dns.adguard.com",
		"dns-unfiltered.adguard.com",
		"dns-family.adguard.com",
		"*.adguard-dns.io",
	}

	testCases := []struct {
		name                 string
		connectionServerName string
		expectedLabelValue   string
		wildcards            []string
		DNSNames             []string
	}{{
		name:                 "empty",
		connectionServerName: "",
		expectedLabelValue:   serverName + ": other",
		wildcards:            wildcards,
		DNSNames:             dnsNames,
	}, {
		name:                 "other",
		connectionServerName: "test",
		expectedLabelValue:   serverName + ": other",
		wildcards:            wildcards,
		DNSNames:             dnsNames,
	}, {
		name:                 "public_dns_hostnames_sni",
		connectionServerName: "dns.adguard.com",
		expectedLabelValue:   serverName + ": dns.adguard.com",
		wildcards:            wildcards,
		DNSNames:             dnsNames,
	}, {
		name:                 "public_dns_hostnames_cert",
		connectionServerName: "",
		expectedLabelValue:   serverName + ": dns.adguard.com",
		wildcards:            nil,
		DNSNames:             dnsNames,
	}, {
		name:                 "public_dns_hostnames_cert_wildcards",
		connectionServerName: "test.adguard-dns.io",
		expectedLabelValue:   serverName + ": *.adguard-dns.io",
		wildcards:            nil,
		DNSNames:             dnsNames,
	}, {
		name:                 "public_dns_ip",
		connectionServerName: "94.140.14.14",
		expectedLabelValue:   serverName + ": 94.140.14.14",
		wildcards:            wildcards,
		DNSNames:             []string{"94.140.14.14"},
	}, {
		name:                 "private_dns",
		connectionServerName: "test.d.adguard-dns.com",
		expectedLabelValue:   serverName + ": d.adguard-dns.com",
		wildcards:            wildcards,
		DNSNames:             dnsNames,
	}, {
		name:                 "private_dns_cert",
		connectionServerName: "test.d.adguard-dns.com",
		expectedLabelValue:   serverName + ": d.adguard-dns.com",
		wildcards:            wildcards,
		DNSNames:             dnsNames,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			x509Cert := x509.Certificate{}
			if tc.DNSNames != nil {
				x509Cert.DNSNames = append(x509Cert.DNSNames, tc.DNSNames...)
			}

			cert := tls.Certificate{Leaf: &x509Cert}

			listener := metrics.TLSMetricsAfterHandshake(
				"",
				serverName,
				tc.wildcards,
				[]tls.Certificate{cert},
			)

			err := listener(tls.ConnectionState{ServerName: tc.connectionServerName})

			require.NoError(t, err)

			metricFamilies, err := prometheus.DefaultGatherer.Gather()
			require.NoError(t, err)
			require.NotNil(t, metricFamilies)

			assertLabelValue(t, metricFamilies, tc.expectedLabelValue)
		})
	}
}

func assertLabelValue(
	t *testing.T,
	metricFamilies []*io_prometheus_client.MetricFamily,
	wantLabel string,
) (ok bool) {
	t.Helper()

outerLoop:
	for _, family := range metricFamilies {
		if family.GetName() != "dns_tls_handshake_total" {
			continue
		}

		for _, m := range family.GetMetric() {
			for _, p := range m.GetLabel() {
				if p.GetName() != "server_name" || wantLabel != p.GetValue() {
					continue
				}

				ok = true

				break outerLoop
			}
		}
	}

	return assert.Truef(t, ok, "%s not found in server name labels", wantLabel)
}
