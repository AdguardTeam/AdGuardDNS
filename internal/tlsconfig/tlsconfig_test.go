package tlsconfig_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/require"
)

// testTimeout is the common timeout for tests and contexts.
const testTimeout = 1 * time.Second

// testLogger is the common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

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
