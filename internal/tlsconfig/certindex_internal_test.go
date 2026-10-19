package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Common domain names used for testing.
const (
	testDomainName        = "a.test"
	testDomainNameAlt     = "b.test"
	testDomainNameIP      = "192.0.2.1"
	testDomainNameUnknown = "unknown.test"
)

// Common [agd.CertificateName]s used for testing.
const (
	testCertName        agd.CertificateName = "cert-a"
	testCertNameAlt     agd.CertificateName = "cert-b"
	testCertNameIP      agd.CertificateName = "cert-ip"
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
	testCertIP = &tls.Certificate{
		Leaf: &x509.Certificate{
			IPAddresses: []net.IP{testAddr.AsSlice()},
			Version:     tls.VersionTLS13,
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

	idx := newCertIndex(testLogger)
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

// Common network-related data used for tests.
var (
	testAddr       = netip.MustParseAddr(testDomainNameIP)
	testInvalidCHI = &tls.ClientHelloInfo{
		ServerName:        testDomainNameUnknown,
		SupportedVersions: []uint16{tls.VersionTLS13},
		Conn:              NewAddrConn(testAddr),
	}
)

func TestCertIndex_CertFor(t *testing.T) {
	var (
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
			pref: netip.PrefixFrom(testAddr, 32),
		},
		testCertNameAlt: {
			data: &certData{
				cert:     testCertAlt,
				certPath: testDomainNameAlt + "_path",
				keyPath:  testDomainNameAlt + "_path",
			},
			pref: netip.PrefixFrom(addrAlt, 32),
		},
		testCertNameIP: {
			data: &certData{
				cert:     testCertIP,
				certPath: testDomainNameIP + "_path",
				keyPath:  testDomainNameIP + "_path",
			},
			pref: netip.PrefixFrom(testAddr, 32),
		},
	}

	idx := newCertIndex(testLogger)
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
			Conn:              NewAddrConn(testAddr),
		},
		wantCert:   testCert,
		wantErrMsg: "",
		name:       "success",
	}, {
		chi: &tls.ClientHelloInfo{
			ServerName:        testDomainNameAlt,
			SupportedVersions: []uint16{tls.VersionTLS13},
			Conn:              NewAddrConn(addrAlt),
		},
		wantCert:   testCertAlt,
		wantErrMsg: "",
		name:       "success_alternative",
	}, {
		chi: &tls.ClientHelloInfo{
			ServerName:        testDomainNameUnknown,
			SupportedVersions: []uint16{tls.VersionTLS13},
			Conn:              NewAddrConn(addrUnknown),
		},
		wantCert:   nil,
		wantErrMsg: "no certificate found for " + addrUnknown.String(),
		name:       "fail_unknown",
	}, {
		chi: &tls.ClientHelloInfo{
			ServerName:        testAddr.String(),
			SupportedVersions: []uint16{tls.VersionTLS13},
			Conn:              NewAddrConn(testAddr),
		},
		wantCert:   testCertIP,
		wantErrMsg: "",
		name:       "success_ip",
	}, {
		chi: &tls.ClientHelloInfo{
			SupportedVersions: []uint16{tls.VersionTLS13},
			Conn:              NewAddrConn(testAddr),
		},
		wantCert:   testCertIP,
		wantErrMsg: "",
		name:       "success_ip_no_servername",
	}, {
		chi: &tls.ClientHelloInfo{
			SupportedVersions: []uint16{tls.VersionTLS13},
			Conn:              NewAddrConn(addrAlt),
		},
		wantCert:   nil,
		wantErrMsg: errCertNotFound.Error(),
		name:       "fail_cert_no_ip",
	}, {
		chi:        testInvalidCHI,
		wantCert:   nil,
		wantErrMsg: errCertNotFound.Error(),
		name:       "fail_cert_not_found",
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

// testDebugLogger is a logger used for testing with debug level.
var testDebugLogger = slogutil.New(&slogutil.Config{
	Level:  slog.LevelDebug,
	Output: io.Discard,
})

func BenchmarkCertIndex_CertFor(b *testing.B) {
	idx := newCertIndex(testDebugLogger)
	idx.add(testCertName, &certData{cert: testCert})
	idx.bind(testCertName, netip.PrefixFrom(testAddr, testAddr.BitLen()))

	chiOK := &tls.ClientHelloInfo{
		ServerName:        testDomainName,
		SupportedVersions: []uint16{tls.VersionTLS13},
		Conn:              NewAddrConn(testAddr),
	}

	b.Run("success", func(b *testing.B) {
		// Warmup to fill the pools and the slices.
		_, err := idx.certFor(chiOK)
		require.NoError(b, err)

		var cert *tls.Certificate

		b.ReportAllocs()
		for b.Loop() {
			cert, err = idx.certFor(chiOK)
		}
		require.NoError(b, err)

		assert.Equal(b, testCert, cert)
	})

	b.Run("unsupported", func(b *testing.B) {
		// Warmup to fill the pools and the slices.
		_, err := idx.certFor(testInvalidCHI)
		require.Error(b, err)

		var cert *tls.Certificate

		b.ReportAllocs()
		for b.Loop() {
			cert, err = idx.certFor(testInvalidCHI)
		}
		require.Nil(b, cert)
		require.Error(b, err)
	})

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig
	//	cpu: AMD Ryzen AI 9 HX PRO 370 w/ Radeon 890M
	//	BenchmarkCertIndex_CertFor/success-24            3426706               336.1 ns/op           288 B/op         10 allocs/op
	//	BenchmarkCertIndex_CertFor/unsupported-24         652532              1800 ns/op             828 B/op         24 allocs/op
}

func BenchmarkCertIndex_CertFor_multiUnsupported(b *testing.B) {
	// Create more certificates than the default error slice length to cause the
	// error slice to grow.
	const nCerts = defaultErrSliceLen + 1

	idx := newCertIndex(testDebugLogger)
	for i := range nCerts {
		name := agd.CertificateName(fmt.Sprintf("bench-cert-%d", i))

		idx.add(name, &certData{cert: testCert})
		idx.bind(name, netip.PrefixFrom(testAddr, testAddr.BitLen()))
	}

	// Warmup to fill the pools and the slices.
	_, err := idx.certFor(testInvalidCHI)
	require.Error(b, err)

	b.ReportAllocs()
	for b.Loop() {
		_, err = idx.certFor(testInvalidCHI)
	}
	require.Error(b, err)

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig
	//	cpu: AMD Ryzen AI 9 HX PRO 370 w/ Radeon 890M
	//	BenchmarkCertIndex_CertFor_multiUnsupported-24             78862             22298 ns/op           18460 B/op        239 allocs/op
}
