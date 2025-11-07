package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Common domain names used for testing.
const (
	testDomainName        = "a.test"
	testDomainNameAlt     = "b.test"
	testDomainNameUnknown = "unknown.test"
)

// Common [agd.CertificateName]s used for testing.
const (
	testCertName        agd.CertificateName = "cert-a"
	testCertNameAlt     agd.CertificateName = "cert-b"
	testCertNameUnknown agd.CertificateName = "cert-unknown"
)

// Common [tls.Certificate]s used for testing.
var (
	testCert = &tls.Certificate{
		Leaf: &x509.Certificate{
			DNSNames: []string{testDomainName},
			Version:  tls.VersionTLS13,
		},
	}
	testCertAlt = &tls.Certificate{
		Leaf: &x509.Certificate{
			DNSNames: []string{testDomainNameAlt},
			Version:  tls.VersionTLS13,
		},
	}
)

func TestCertIndex(t *testing.T) {
	certs := map[agd.CertificateName]*certData{
		testCertName: {
			cert:     testCert,
			certPath: testDomainName + "_path",
			keyPath:  testDomainName + "_path",
		},
		testCertNameAlt: {
			cert:     testCertAlt,
			certPath: testDomainNameAlt + "_path",
			keyPath:  testDomainNameAlt + "_path",
		},
	}

	idx := newCertIndex()
	for name, cd := range certs {
		idx.add(name, cd)
	}

	t.Run("contains", func(t *testing.T) {
		assert.True(t, idx.contains(testCertName))
		assert.True(t, idx.contains(testCertNameAlt))
		assert.False(t, idx.contains(testCertNameUnknown))
	})

	t.Run("count", func(t *testing.T) {
		assert.Equal(t, len(certs), idx.count())
	})

	t.Run("stored", func(t *testing.T) {
		want := []*tls.Certificate{testCert, testCertAlt}

		assert.ElementsMatch(t, want, idx.stored())
	})

	t.Run("rangeFn", func(t *testing.T) {
		n := 0
		idx.rangeFn(func(name agd.CertificateName, cd *certData) (cont bool) {
			require.Contains(t, certs, name)
			assert.Equal(t, cd, certs[name])

			n++

			return true
		})

		assert.Equal(t, len(certs), n)
	})
}

func TestCertIndex_CertFor(t *testing.T) {
	var (
		addr        = netip.MustParseAddr("192.0.2.1")
		addrAlt     = netip.MustParseAddr("192.0.2.2")
		addrUnknown = netip.MustParseAddr("192.0.2.3")
	)

	certs := map[agd.CertificateName]struct {
		data *certData
		pref netip.Prefix
	}{
		testCertName: {
			data: &certData{
				cert:     testCert,
				certPath: testDomainName + "_path",
				keyPath:  testDomainName + "_path",
			},
			pref: netip.PrefixFrom(addr, 32),
		},
		testCertNameAlt: {
			data: &certData{
				cert:     testCertAlt,
				certPath: testDomainNameAlt + "_path",
				keyPath:  testDomainNameAlt + "_path",
			},
			pref: netip.PrefixFrom(addrAlt, 32),
		},
	}

	idx := newCertIndex()
	for name, cd := range certs {
		idx.add(name, cd.data)

		added := idx.bind(name, cd.pref)
		require.True(t, added)
	}

	testCases := []struct {
		chi        *tls.ClientHelloInfo
		wantCert   *tls.Certificate
		wantErrMsg string
		name       string
	}{{
		chi: &tls.ClientHelloInfo{
			ServerName:        testDomainName,
			SupportedVersions: []uint16{tls.VersionTLS13},
			Conn:              NewLocalAddrConn(addr),
		},
		wantCert:   testCert,
		wantErrMsg: "",
		name:       "success",
	}, {
		chi: &tls.ClientHelloInfo{
			ServerName:        testDomainNameAlt,
			SupportedVersions: []uint16{tls.VersionTLS13},
			Conn:              NewLocalAddrConn(addrAlt),
		},
		wantCert:   testCertAlt,
		wantErrMsg: "",
		name:       "success_alternative",
	}, {
		chi: &tls.ClientHelloInfo{
			ServerName:        testDomainNameUnknown,
			SupportedVersions: []uint16{tls.VersionTLS13},
			Conn:              NewLocalAddrConn(addrUnknown),
		},
		wantCert:   nil,
		wantErrMsg: "no certificate found for " + addrUnknown.String(),
		name:       "fail_unknown",
	}, {
		chi: &tls.ClientHelloInfo{
			ServerName:        testDomainNameUnknown,
			SupportedVersions: []uint16{tls.VersionTLS12},
			Conn:              NewLocalAddrConn(addr),
		},
		wantCert: nil,
		wantErrMsg: "certificate is not valid for requested server name: " +
			"x509: certificate is valid for " + testDomainName +
			", not " + testDomainNameUnknown,
		name: "fail_server_name",
	}}

	t.Run("certFor", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				got, err := idx.certFor(tc.chi)
				testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
				assert.Equal(t, tc.wantCert, got)
			})
		}
	})
}
