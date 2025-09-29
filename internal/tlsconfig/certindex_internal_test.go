package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertIndex(t *testing.T) {
	const (
		domainA = "a.com"
		domainB = "b.org"
	)

	var (
		pathsDomainA = &certPaths{
			certPath: domainA + "_path",
			keyPath:  domainA + "_path",
		}
		pathsDomainB = &certPaths{
			certPath: domainB + "_path",
			keyPath:  domainB + "_path",
		}
		nonAddedPaths = &certPaths{
			certPath: "non_added_path",
			keyPath:  "non_added_path",
		}
	)

	certDomainA := &tls.Certificate{Leaf: &x509.Certificate{
		DNSNames: []string{domainA},
		Version:  tls.VersionTLS13,
	}}

	certDomainB := &tls.Certificate{Leaf: &x509.Certificate{
		DNSNames: []string{domainB},
		Version:  tls.VersionTLS13,
	}}

	certWithPaths := []struct {
		cert  *tls.Certificate
		paths *certPaths
	}{{
		cert:  certDomainA,
		paths: pathsDomainA,
	}, {
		cert:  certDomainB,
		paths: pathsDomainB,
	}}

	idx := &certIndex{}
	for _, cp := range certWithPaths {
		idx.add(cp.cert, cp.paths)
	}

	assert.True(t, idx.contains(pathsDomainA))

	copyPathsDomainsB := *pathsDomainB
	assert.True(t, idx.contains(&copyPathsDomainsB))
	assert.False(t, idx.contains(nonAddedPaths))
	assert.Equal(t, len(certWithPaths), idx.count())

	got, err := idx.certFor(&tls.ClientHelloInfo{
		ServerName:        domainA,
		SupportedVersions: []uint16{tls.VersionTLS13},
	})
	require.NoError(t, err)

	assert.Equal(t, certDomainA, got)

	got, err = idx.certFor(&tls.ClientHelloInfo{
		ServerName:        domainB,
		SupportedVersions: []uint16{tls.VersionTLS13},
	})
	require.NoError(t, err)

	assert.Equal(t, certDomainB, got)
	assert.Equal(t, []*tls.Certificate{certDomainA, certDomainB}, idx.stored())

	i := 0
	idx.rangeFn(func(c *tls.Certificate, cp *certPaths) (cont bool) {
		assert.Equal(t, certWithPaths[i].cert, c)
		assert.Equal(t, certWithPaths[i].paths, cp)

		i++

		return true
	})
}
