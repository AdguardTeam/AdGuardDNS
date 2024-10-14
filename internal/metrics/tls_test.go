package metrics_test

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLSMetricsAfterHandshake(t *testing.T) {
	serverName := "test_server"
	devDomains := []string{"d.adguard-dns.com"}
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
		devDomains           []string
		DNSNames             []string
	}{{
		name:                 "empty",
		connectionServerName: "",
		expectedLabelValue:   serverName + ": other",
		devDomains:           devDomains,
		DNSNames:             dnsNames,
	}, {
		name:                 "other",
		connectionServerName: "test",
		expectedLabelValue:   serverName + ": other",
		devDomains:           devDomains,
		DNSNames:             dnsNames,
	}, {
		name:                 "public_dns_hostnames_sni",
		connectionServerName: "dns.adguard.com",
		expectedLabelValue:   serverName + ": dns.adguard.com",
		devDomains:           devDomains,
		DNSNames:             dnsNames,
	}, {
		name:                 "public_dns_hostnames_cert",
		connectionServerName: "",
		expectedLabelValue:   serverName + ": dns.adguard.com",
		devDomains:           nil,
		DNSNames:             dnsNames,
	}, {
		name:                 "public_dns_hostnames_cert_wildcards",
		connectionServerName: "test.adguard-dns.io",
		expectedLabelValue:   serverName + ": *.adguard-dns.io",
		devDomains:           nil,
		DNSNames:             dnsNames,
	}, {
		name:                 "public_dns_ip",
		connectionServerName: "94.140.14.14",
		expectedLabelValue:   serverName + ": 94.140.14.14",
		devDomains:           devDomains,
		DNSNames:             []string{"94.140.14.14"},
	}, {
		name:                 "private_dns",
		connectionServerName: "test.d.adguard-dns.com",
		expectedLabelValue:   serverName + ": d.adguard-dns.com",
		devDomains:           devDomains,
		DNSNames:             dnsNames,
	}, {
		name:                 "private_dns_cert",
		connectionServerName: "test.d.adguard-dns.com",
		expectedLabelValue:   serverName + ": d.adguard-dns.com",
		devDomains:           devDomains,
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
				tc.devDomains,
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

	for _, family := range metricFamilies {
		if family.GetName() != "dns_tls_handshake_total" {
			continue
		}

		if ok = findLabel(family.GetMetric(), wantLabel); ok {
			break
		}
	}

	return assert.Truef(t, ok, "%s not found in server name labels", wantLabel)
}

// findLabel is a helper function to find label in metrics.
func findLabel(ms []*io_prometheus_client.Metric, label string) (ok bool) {
	for _, m := range ms {
		for _, p := range m.GetLabel() {
			if p.GetName() == "server_name" && label == p.GetValue() {
				return true
			}
		}
	}

	return false
}

func TestTLSMetricsBeforeHandshake(t *testing.T) {
	f := metrics.TLSMetricsBeforeHandshake("srv-name")

	var conf *tls.Config
	var err error
	require.NotPanics(t, func() {
		conf, err = f(&tls.ClientHelloInfo{
			SupportedProtos: []string{"\xC0\xC1\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"},
		})
	})
	require.NoError(t, err)

	assert.Nil(t, conf)
}
