package tlsconfig_test

import (
	"cmp"
	"crypto/rand"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

// newManager is a helper for creating the TLS manager for tests.  c may be nil,
// and all zero-value fields in c are replaced with defaults for tests.
func newManager(tb testing.TB, c *tlsconfig.DefaultManagerConfig) (m *tlsconfig.DefaultManager) {
	tb.Helper()

	c = cmp.Or(c, &tlsconfig.DefaultManagerConfig{})

	c.Logger = cmp.Or(c.Logger, testLogger)

	c.ErrColl = cmp.Or[errcoll.Interface](c.ErrColl, agdtest.NewErrorCollector())
	c.Metrics = cmp.Or[tlsconfig.ManagerMetrics](c.Metrics, tlsconfig.EmptyManagerMetrics{})
	c.TicketDB = cmp.Or[tlsconfig.TicketDB](c.TicketDB, tlsconfig.EmptyTicketDB{})

	m, err := tlsconfig.NewDefaultManager(c)
	require.NoError(tb, err)

	return m
}

func TestDefaultManager_Refresh(t *testing.T) {
	t.Parallel()

	const (
		snBefore int64 = 1
		snAfter  int64 = 2
	)

	m := newManager(t, nil)

	certDER, key := newCertAndKey(t, snBefore)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	writeCertAndKey(t, certDER, certPath, key, keyPath)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	err := m.Add(ctx, certPath, keyPath, false)
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

func TestDefaultManager_Remove(t *testing.T) {
	t.Parallel()

	certDER, key := newCertAndKey(t, 1)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	writeCertAndKey(t, certDER, certPath, key, keyPath)

	m := newManager(t, nil)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	err := m.Add(ctx, certPath, keyPath, false)
	require.NoError(t, err)

	chi := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
	}

	c := m.Clone()
	_, err = c.GetCertificate(chi)
	assert.NoError(t, err)

	ctx = testutil.ContextWithTimeout(t, testTimeout)
	err = m.Remove(ctx, certPath, keyPath, false)
	require.NoError(t, err)

	c = m.Clone()
	_, err = c.GetCertificate(chi)
	testutil.AssertErrorMsg(t, "no certificates", err)
}

func TestDefaultManager_RotateTickets(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	sessKeyPath := filepath.Join(tmpDir, "sess.key")
	writeSessionKey(t, sessKeyPath)

	m := newManager(t, &tlsconfig.DefaultManagerConfig{
		TicketDB: tlsconfig.NewLocalTicketDB(&tlsconfig.LocalTicketDBConfig{
			Paths: []string{sessKeyPath},
		}),
	})

	certDER, key := newCertAndKey(t, 1)

	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	writeCertAndKey(t, certDER, certPath, key, keyPath)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	err := m.Add(ctx, certPath, keyPath, false)
	require.NoError(t, err)

	err = m.RotateTickets(ctx)
	require.NoError(t, err)

	// TODO(s.chzhen):  Find a way to test session ticket changes.
}
