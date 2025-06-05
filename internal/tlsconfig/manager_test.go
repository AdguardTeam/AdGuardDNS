package tlsconfig_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is the common timeout for tests and contexts.
const testTimeout = 1 * time.Second

// newCertAndKey is a helper function that generates certificate and key.
func newCertAndKey(tb testing.TB, n int64) (certDER []byte, key *rsa.PrivateKey) {
	tb.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(tb, err)

	certTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(n),
	}

	certDER, err = x509.CreateCertificate(rand.Reader, certTmpl, certTmpl, &key.PublicKey, key)
	require.NoError(tb, err)

	return certDER, key
}

// writeCertAndKey is a helper function that writes certificate and key to
// specified paths.
func writeCertAndKey(
	tb testing.TB,
	certDER []byte,
	certPath string,
	key *rsa.PrivateKey,
	keyPath string,
) {
	tb.Helper()

	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE, 0o600)
	require.NoError(tb, err)

	defer func() {
		err = certFile.Close()
		require.NoError(tb, err)
	}()

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(tb, err)

	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE, 0o600)
	require.NoError(tb, err)

	defer func() {
		err = keyFile.Close()
		require.NoError(tb, err)
	}()

	err = pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	require.NoError(tb, err)
}

// writeSesionKey is a helper function that writes generated session key to
// specified path.
func writeSessionKey(tb testing.TB, sessKeyPath string) {
	tb.Helper()

	var sessKey [32]byte
	_, err := rand.Read(sessKey[:])
	require.NoError(tb, err)

	keyFile, err := os.OpenFile(sessKeyPath, os.O_WRONLY|os.O_CREATE, 0o600)
	require.NoError(tb, err)

	defer func() {
		err = keyFile.Close()
		require.NoError(tb, err)
	}()

	_, err = keyFile.Write(sessKey[:])
	require.NoError(tb, err)
}

// assertCertSerialNumber is a helper function that checks serial number of the
// TLS certificate.
func assertCertSerialNumber(tb testing.TB, conf *tls.Config, wantSN int64) {
	tb.Helper()

	cert, err := conf.GetCertificate(&tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
	})
	require.NoError(tb, err)

	assert.Equal(tb, wantSN, cert.Leaf.SerialNumber.Int64())
}

func TestDefaultManager_Refresh(t *testing.T) {
	t.Parallel()

	const (
		snBefore int64 = 1
		snAfter  int64 = 2
	)

	m, err := tlsconfig.NewDefaultManager(&tlsconfig.DefaultManagerConfig{
		Logger:  slogutil.NewDiscardLogger(),
		ErrColl: agdtest.NewErrorCollector(),
		Metrics: tlsconfig.EmptyMetrics{},
	})
	require.NoError(t, err)

	certDER, key := newCertAndKey(t, snBefore)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	writeCertAndKey(t, certDER, certPath, key, keyPath)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	err = m.Add(ctx, certPath, keyPath)
	require.NoError(t, err)

	conf := m.Clone()
	confWithMetrics := m.CloneWithMetrics("", "", nil)

	assertCertSerialNumber(t, conf, snBefore)
	assertCertSerialNumber(t, confWithMetrics, snBefore)

	certDER, key = newCertAndKey(t, snAfter)
	writeCertAndKey(t, certDER, certPath, key, keyPath)

	err = m.Refresh(ctx)
	require.NoError(t, err)

	assertCertSerialNumber(t, conf, snAfter)
	assertCertSerialNumber(t, confWithMetrics, snAfter)
}

func TestDefaultManager_RotateTickets(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	sessKeyPath := filepath.Join(tmpDir, "sess.key")
	writeSessionKey(t, sessKeyPath)

	m, err := tlsconfig.NewDefaultManager(&tlsconfig.DefaultManagerConfig{
		Logger:  slogutil.NewDiscardLogger(),
		ErrColl: agdtest.NewErrorCollector(),
		Metrics: tlsconfig.EmptyMetrics{},
	})
	require.NoError(t, err)

	certDER, key := newCertAndKey(t, 1)

	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	writeCertAndKey(t, certDER, certPath, key, keyPath)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	err = m.Add(ctx, certPath, keyPath)
	require.NoError(t, err)

	db := tlsconfig.NewLocalTicketDB(&tlsconfig.LocalTicketDBConfig{
		Paths: []string{sessKeyPath},
	})

	err = m.RotateTickets(ctx, db)
	require.NoError(t, err)

	// TODO(s.chzhen):  Find a way to test session ticket changes.
}
