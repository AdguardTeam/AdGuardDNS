package tlsconfig_test

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/faketime"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCertName is the common certificate name for tests.
const testCertName agd.CertificateName = "cert1234"

// testProfileID is the common profile ID for tests.
const testProfileID agd.ProfileID = "prof1234"

// testWellKnownPath is the well-known certificate validation path for tests.
const testWellKnownPath = "/.well-known/pki-validation/abcd1234"

// testRetryIvl is the retry interval for tests.
const testRetryIvl = 1 * time.Minute

// Domains for tests.
const (
	testDomain            = "domain.example"
	testDomainWildcardTop = "wildcard.example"
	testDomainWildcard    = "test." + testDomainWildcardTop
	testWildcard          = "*." + testDomainWildcardTop
)

// testDomains are the common domains and wildcards for tests.
var testDomains = []string{
	testDomain,
	"*." + testDomain,
	testWildcard,
}

// Time values for tests.
var (
	testTimeExpired = testTimeNow.Add(-1 * timeutil.Day)
	testTimeFuture  = testTimeNow.Add(1 * timeutil.Day)
	testTimeNow     = time.Now()
)

// Custom-domain states for tests.
var (
	testStateDisabled = &agd.CustomDomainStateCurrent{
		NotBefore: testTimeNow.Add(-1 * timeutil.Day),
		NotAfter:  testTimeNow.Add(1 * timeutil.Day),
		CertName:  testCertName,
		Enabled:   false,
	}

	testStateExpired = &agd.CustomDomainStateCurrent{
		NotBefore: testTimeExpired.Add(-1 * timeutil.Day),
		NotAfter:  testTimeExpired,
		CertName:  testCertName,
		Enabled:   true,
	}

	testStateFuture = &agd.CustomDomainStateCurrent{
		NotBefore: testTimeFuture.Add(-1 * timeutil.Day),
		NotAfter:  testTimeFuture,
		CertName:  testCertName,
		Enabled:   true,
	}

	testStateOK = &agd.CustomDomainStateCurrent{
		NotBefore: testTimeNow.Add(-1 * timeutil.Day),
		NotAfter:  testTimeNow.Add(1 * timeutil.Day),
		CertName:  testCertName,
		Enabled:   true,
	}
)

// newCustomDomainDB is a helper for creating the custom-domain database for
// tests.  c may be nil, and all zero-value fields in c are replaced with
// defaults for tests.
func newCustomDomainDB(
	tb testing.TB,
	c *tlsconfig.CustomDomainDBConfig,
) (db *tlsconfig.CustomDomainDB) {
	tb.Helper()

	c = cmp.Or(c, &tlsconfig.CustomDomainDBConfig{})

	c.Logger = cmp.Or(c.Logger, testLogger)

	c.Clock = cmp.Or[timeutil.Clock](c.Clock, timeutil.SystemClock{})
	c.ErrColl = cmp.Or[errcoll.Interface](c.ErrColl, agdtest.NewErrorCollector())
	c.Manager = cmp.Or[tlsconfig.Manager](c.Manager, tlsconfig.EmptyManager{})
	c.Metrics = cmp.Or[tlsconfig.CustomDomainDBMetrics](
		c.Metrics,
		tlsconfig.EmptyCustomDomainDBMetrics{},
	)
	c.Storage = cmp.Or[tlsconfig.CustomDomainStorage](
		c.Storage,
		tlsconfig.EmptyCustomDomainStorage{},
	)

	c.CacheDirPath = cmp.Or(c.CacheDirPath, tb.TempDir())

	c.InitialRetryIvl = cmp.Or(c.InitialRetryIvl, testRetryIvl)
	c.MaxRetryIvl = cmp.Or(c.MaxRetryIvl, 1*time.Hour)

	db, err := tlsconfig.NewCustomDomainDB(c)
	require.NoError(tb, err)

	return db
}

func TestCustomDomainDB_IsValidWellKnownRequest(t *testing.T) {
	t.Parallel()

	db := newCustomDomainDB(t, nil)

	httpReq := httptest.NewRequest(http.MethodGet, testWellKnownPath, nil)

	require.True(t, t.Run("initial", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, testTimeout)
		ok := db.IsValidWellKnownRequest(ctx, httpReq)
		assert.False(t, ok)
	}))

	require.True(t, t.Run("new_profile", func(t *testing.T) {
		s := &agd.CustomDomainStatePending{
			Expire:        time.Now().Add(1 * time.Hour),
			WellKnownPath: testWellKnownPath,
		}

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.SetWellKnownPath(ctx, s)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		ok := db.IsValidWellKnownRequest(ctx, httpReq)
		assert.True(t, ok)

		// Now expire it.
		s = &agd.CustomDomainStatePending{
			Expire:        time.Now().Add(-1 * time.Hour),
			WellKnownPath: testWellKnownPath,
		}

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		db.SetWellKnownPath(ctx, s)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		ok = db.IsValidWellKnownRequest(ctx, httpReq)
		assert.False(t, ok)
	}))

	require.True(t, t.Run("invalid", func(t *testing.T) {
		s := &agd.CustomDomainStatePending{
			Expire:        time.Now().Add(1 * time.Hour),
			WellKnownPath: testWellKnownPath,
		}

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.SetWellKnownPath(ctx, s)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		ok := db.IsValidWellKnownRequest(ctx, httpReq)
		require.True(t, ok)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		postReq := httpReq.Clone(ctx)
		postReq.Method = http.MethodPost

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		ok = db.IsValidWellKnownRequest(ctx, postReq)
		assert.False(t, ok)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		tlsReq := httpReq.Clone(ctx)
		tlsReq.TLS = &tls.ConnectionState{}

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		ok = db.IsValidWellKnownRequest(ctx, tlsReq)
		assert.False(t, ok)
	}))

	require.True(t, t.Run("delete_all", func(t *testing.T) {
		s := &agd.CustomDomainStatePending{
			Expire:        time.Now().Add(1 * time.Hour),
			WellKnownPath: testWellKnownPath,
		}

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.SetWellKnownPath(ctx, s)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		ok := db.IsValidWellKnownRequest(ctx, httpReq)
		require.True(t, ok)

		// Now delete all.
		ctx = testutil.ContextWithTimeout(t, testTimeout)
		db.DeleteAllWellKnownPaths(ctx)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		ok = db.IsValidWellKnownRequest(ctx, httpReq)
		assert.False(t, ok)
	}))
}

func TestCustomDomainDB_IsValidWellKnownRequest_expiredLater(t *testing.T) {
	t.Parallel()

	var (
		expire     = testTimeNow
		nowEarlier = testTimeExpired
		nowLater   = expire.Add(1 * timeutil.Day)
	)

	nowCh := make(chan time.Time, 1)
	clock := &faketime.Clock{
		OnNow: func() (now time.Time) {
			now, ok := testutil.RequireReceive(t, nowCh, testTimeout)
			require.True(t, ok)

			return now
		},
	}

	db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
		Clock: clock,
	})

	s := &agd.CustomDomainStatePending{
		Expire:        expire,
		WellKnownPath: testWellKnownPath,
	}

	nowCh <- nowEarlier
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	db.SetWellKnownPath(ctx, s)

	httpReq := httptest.NewRequest(http.MethodGet, testWellKnownPath, nil)

	nowCh <- nowEarlier
	ctx = testutil.ContextWithTimeout(t, testTimeout)
	ok := db.IsValidWellKnownRequest(ctx, httpReq)
	require.True(t, ok)

	nowCh <- nowLater
	ctx = testutil.ContextWithTimeout(t, testTimeout)
	ok = db.IsValidWellKnownRequest(ctx, httpReq)
	assert.False(t, ok)
}

func TestCustomDomainDB_AddCertificate(t *testing.T) {
	t.Parallel()

	clock := &faketime.Clock{
		OnNow: func() (now time.Time) { return testTimeNow },
	}

	testCases := []struct {
		state     *agd.CustomDomainStateCurrent
		name      string
		wantMatch bool
	}{{
		state:     testStateOK,
		name:      "good",
		wantMatch: true,
	}, {
		state:     testStateExpired,
		name:      "expired",
		wantMatch: false,
	}, {
		state:     testStateDisabled,
		name:      "disabled",
		wantMatch: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
				Clock: clock,
			})

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			db.AddCertificate(ctx, testProfileID, testDomains, tc.state)

			assertCustomDomainMatch(t, db, testDomain, tc.wantMatch)
		})
	}
}

// assertCustomDomainMatch is a helper function for checking the result of a
// match.
func assertCustomDomainMatch(
	tb testing.TB,
	db *tlsconfig.CustomDomainDB,
	cliSrvName string,
	wantMatch bool,
) {
	tb.Helper()

	ctx := testutil.ContextWithTimeout(tb, testTimeout)
	matched, profIDs := db.Match(ctx, cliSrvName)
	if wantMatch {
		assert.Equal(tb, testDomain, matched)
		assert.Contains(tb, profIDs, testProfileID)
	} else {
		assert.Empty(tb, matched)
		assert.Nil(tb, profIDs)
	}
}

func TestCustomDomainDB_AddCertificate_specialCases(t *testing.T) {
	t.Parallel()

	clock := &faketime.Clock{
		OnNow: func() (now time.Time) { return testTimeNow },
	}

	t.Run("twice", func(t *testing.T) {
		t.Parallel()

		db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
			Clock: clock,
		})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testProfileID, testDomains, testStateOK)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testProfileID, testDomains, testStateOK)

		assertCustomDomainMatch(t, db, testDomain, true)
	})

	t.Run("disabled", func(t *testing.T) {
		t.Parallel()

		db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
			Clock: clock,
		})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testProfileID, testDomains, testStateOK)

		assertCustomDomainMatch(t, db, testDomain, true)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testProfileID, testDomains, testStateDisabled)

		assertCustomDomainMatch(t, db, testDomain, false)
	})

	t.Run("expired", func(t *testing.T) {
		t.Parallel()

		now := testTimeExpired
		db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
			Clock: &faketime.Clock{
				OnNow: func() (n time.Time) { return now },
			},
		})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testProfileID, testDomains, testStateExpired)

		assertCustomDomainMatch(t, db, testDomain, true)

		now = testTimeNow

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testProfileID, testDomains, testStateExpired)

		assertCustomDomainMatch(t, db, testDomain, false)
	})
}

func TestCustomDomainDB_Match(t *testing.T) {
	t.Parallel()

	db := newCustomDomainDB(t, nil)

	addCtx := testutil.ContextWithTimeout(t, testTimeout)
	db.AddCertificate(addCtx, testProfileID, testDomains, testStateOK)

	testCases := []struct {
		name        string
		cliSrvName  string
		wantMatched string
		wantProfIDs []agd.ProfileID
	}{{
		name:        "match_domain",
		cliSrvName:  testDomain,
		wantMatched: testDomain,
		wantProfIDs: []agd.ProfileID{testProfileID},
	}, {
		name:        "match_wildcard",
		cliSrvName:  testDomainWildcard,
		wantMatched: testWildcard,
		wantProfIDs: []agd.ProfileID{testProfileID},
	}, {
		name:        "no_match",
		cliSrvName:  "other.example",
		wantMatched: "",
		wantProfIDs: nil,
	}, {
		name:        "no_match_wildcard_suf",
		cliSrvName:  testDomainWildcardTop,
		wantMatched: "",
		wantProfIDs: nil,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			matched, profID := db.Match(ctx, tc.cliSrvName)
			assert.Equal(t, tc.wantMatched, matched)
			assert.Equal(t, tc.wantProfIDs, profID)
		})
	}
}

func TestCustomDomainDB_Match_futureCert(t *testing.T) {
	t.Parallel()

	now := testTimeNow
	db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
		Clock: &faketime.Clock{
			OnNow: func() (n time.Time) { return now },
		},
	})

	addCtx := testutil.ContextWithTimeout(t, testTimeout)
	db.AddCertificate(addCtx, testProfileID, testDomains, testStateOK)

	futureState := &agd.CustomDomainStateCurrent{}
	*futureState = *testStateFuture
	futureState.CertName = futureState.CertName + "_future"

	addCtx = testutil.ContextWithTimeout(t, testTimeout)
	db.AddCertificate(addCtx, testProfileID, testDomains, futureState)

	assertCustomDomainMatch(t, db, testDomain, true)

	now = testTimeFuture

	assertCustomDomainMatch(t, db, testDomain, true)
}

// testCustomDomainStorage is the [tlsconfig.CustomDomainStorage] for tests.
type testCustomDomainStorage struct {
	onCertificateData func(
		ctx context.Context,
		certName agd.CertificateName,
	) (cert, key []byte, err error)
}

// type check
var _ tlsconfig.CustomDomainStorage = (*testCustomDomainStorage)(nil)

// CertificateData implements the [tlsconfig.CustomDomainStorage] interface for
// *testCustomDomainStorage
func (s *testCustomDomainStorage) CertificateData(
	ctx context.Context,
	certName agd.CertificateName,
) (cert, key []byte, err error) {
	return s.onCertificateData(ctx, certName)
}

// testManager is the [tlsconfig.Manager] for tests.
type testManager struct {
	onAdd              func(ctx context.Context, certPath, keyPath string, isCustom bool) (err error)
	onClone            func() (c *tls.Config)
	onCloneWithMetrics func(proto, srvName string, deviceDomains []string) (c *tls.Config)
	onRemove           func(ctx context.Context, certPath, keyPath string, isCustom bool) (err error)
}

// type check
var _ tlsconfig.Manager = (*testManager)(nil)

// Add implements the [tlsconfig.Manager] interface for *testManager.
func (m *testManager) Add(ctx context.Context, certPath, keyPath string, isCustom bool) (err error) {
	return m.onAdd(ctx, certPath, keyPath, isCustom)
}

// Clone implements the [tlsconfig.Manager] interface for *testManager.
func (m *testManager) Clone() (c *tls.Config) {
	return m.onClone()
}

// CloneWithMetrics implements the [tlsconfig.Manager] interface for
// *testManager.
func (m *testManager) CloneWithMetrics(
	proto string,
	srvName string,
	deviceDomains []string,
) (c *tls.Config) {
	return m.onCloneWithMetrics(proto, srvName, deviceDomains)
}

// Remove implements the [tlsconfig.Manager] interface for *testManager.
func (m *testManager) Remove(ctx context.Context, certPath, keyPath string, isCustom bool) (err error) {
	return m.onRemove(ctx, certPath, keyPath, isCustom)
}

// newTestManager returns a new *testManager all methods of which panic.
func newTestManager() (m *testManager) {
	return &testManager{
		onAdd: func(ctx context.Context, certPath, keyPath string, isCustom bool) (err error) {
			panic(testutil.UnexpectedCall(ctx, certPath, keyPath, isCustom))
		},
		onClone: func() (c *tls.Config) {
			panic(testutil.UnexpectedCall())
		},
		onCloneWithMetrics: func(proto, srvName string, deviceDomains []string) (c *tls.Config) {
			panic(testutil.UnexpectedCall(proto, srvName, deviceDomains))
		},
		onRemove: func(ctx context.Context, certPath, keyPath string, isCustom bool) (err error) {
			panic(testutil.UnexpectedCall(ctx, certPath, keyPath, isCustom))
		},
	}
}

// assertCertificatePair is a test helper that checks whether certPath is a
// valid PEM-encoded certificate and keyPath is a valid matching PEM-encoded RSA
// private key for that certificate.
func assertCertificatePair(tb testing.TB, certPath, keyPath string) {
	tb.Helper()

	require.FileExists(tb, certPath)
	require.FileExists(tb, keyPath)

	data, err := os.ReadFile(certPath)
	require.NoError(tb, err)

	block, _ := pem.Decode(data)
	require.NotNil(tb, block)

	assert.Equal(tb, "CERTIFICATE", block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(tb, err)

	keyData, err := os.ReadFile(keyPath)
	require.NoError(tb, err)

	keyBlock, _ := pem.Decode(keyData)
	require.NotNil(tb, keyBlock)

	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	require.NoError(tb, err)

	assert.Equal(tb, cert.PublicKey, &key.PublicKey)
}

func TestCustomDomainDB_Refresh(t *testing.T) {
	t.Parallel()

	strg := &testCustomDomainStorage{
		onCertificateData: func(
			ctx context.Context,
			certName agd.CertificateName,
		) (cert, key []byte, err error) {
			assert.Equal(t, testCertName, certName)

			certDER, rsaKey := newCertAndKey(t, 1)

			return certDER, x509.MarshalPKCS1PrivateKey(rsaKey), nil
		},
	}

	cacheDir := t.TempDir()
	wantCertPath, wantKeyPath := newCertAndKeyPaths(cacheDir)

	mgrWithAdd := newTestManager()
	mgrWithAdd.onAdd = func(ctx context.Context, certPath, keyPath string, isCustom bool) (err error) {
		assert.Equal(t, wantCertPath, certPath)
		assert.Equal(t, wantKeyPath, keyPath)
		assert.True(t, isCustom)

		return nil
	}

	mgrWithRemove := newTestManager()
	mgrWithRemove.onRemove = func(ctx context.Context, certPath, keyPath string, isCustom bool) (err error) {
		assert.Equal(t, wantCertPath, certPath)
		assert.Equal(t, wantKeyPath, keyPath)
		assert.True(t, isCustom)

		return nil
	}

	require.True(t, t.Run("success", func(t *testing.T) {
		db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
			Manager:      mgrWithAdd,
			Storage:      strg,
			CacheDirPath: cacheDir,
		})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testProfileID, testDomains, testStateOK)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		err := db.Refresh(ctx)
		require.NoError(t, err)

		assertCustomDomainMatch(t, db, testDomain, true)
		assertCertificatePair(t, wantCertPath, wantKeyPath)
	}))

	require.True(t, t.Run("success_no_update", func(t *testing.T) {
		db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
			Manager:      mgrWithAdd,
			Storage:      strg,
			CacheDirPath: cacheDir,
		})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testProfileID, testDomains, testStateOK)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		err := db.Refresh(ctx)
		require.NoError(t, err)

		assertCustomDomainMatch(t, db, testDomain, true)
		assertCertificatePair(t, wantCertPath, wantKeyPath)
	}))

	require.True(t, t.Run("expire", func(t *testing.T) {
		db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
			Manager:      mgrWithRemove,
			Storage:      strg,
			CacheDirPath: cacheDir,
		})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testProfileID, testDomains, testStateExpired)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		err := db.Refresh(ctx)
		require.NoError(t, err)

		assertCustomDomainMatch(t, db, testDomain, false)
		assert.NoFileExists(t, wantCertPath)
		assert.NoFileExists(t, wantKeyPath)
	}))
}

// newCertAndKeyPaths is a helper that returns paths for the certificate and
// the key using the test's temporary directory.
func newCertAndKeyPaths(cacheDir string) (certPath, keyPath string) {
	return filepath.Join(cacheDir, string(testCertName)+tlsconfig.CustomDomainCertExt),
		filepath.Join(cacheDir, string(testCertName)+tlsconfig.CustomDomainKeyExt)
}

func TestCustomDomainDB_Refresh_retry(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	wantCertPath, wantKeyPath := newCertAndKeyPaths(cacheDir)

	mgr := newTestManager()
	mgr.onAdd = func(ctx context.Context, certPath, keyPath string, isCustom bool) (err error) {
		assert.Equal(t, wantCertPath, certPath)
		assert.Equal(t, wantKeyPath, keyPath)
		assert.True(t, isCustom)

		return nil
	}
	mgr.onRemove = func(ctx context.Context, certPath, keyPath string, isCustom bool) (err error) {
		assert.Equal(t, wantCertPath, certPath)
		assert.Equal(t, wantKeyPath, keyPath)
		assert.True(t, isCustom)

		return nil
	}

	shouldCall := true
	var strgErr error
	strg := &testCustomDomainStorage{
		onCertificateData: func(
			ctx context.Context,
			certName agd.CertificateName,
		) (cert, key []byte, err error) {
			if !shouldCall {
				panic(testutil.UnexpectedCall(ctx, certName))
			}

			if strgErr != nil {
				return nil, nil, strgErr
			}

			assert.Equal(t, testCertName, certName)

			certDER, rsaKey := newCertAndKey(t, 1)

			return certDER, x509.MarshalPKCS1PrivateKey(rsaKey), nil
		},
	}

	now := testTimeNow
	db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
		Clock: &faketime.Clock{
			OnNow: func() (n time.Time) { return now },
		},
		Manager:      mgr,
		Storage:      strg,
		CacheDirPath: cacheDir,
		ErrColl: &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, err error) {},
		},
	})

	require.True(t, t.Run("rate_limited", func(t *testing.T) {
		rlErr := &profiledb.RateLimitedError{}

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testProfileID, testDomains, testStateOK)

		strgErr = rlErr
		ctx = testutil.ContextWithTimeout(t, testTimeout)
		err := db.Refresh(ctx)
		assert.Error(t, err)
		assert.NoFileExists(t, wantCertPath)
		assert.NoFileExists(t, wantKeyPath)

		now = now.Add(testRetryIvl)
		strgErr = nil
		ctx = testutil.ContextWithTimeout(t, testTimeout)
		err = db.Refresh(ctx)
		assert.NoError(t, err)
		assertCertificatePair(t, wantCertPath, wantKeyPath)

		// Make sure that the retry has been deleted.
		now = now.Add(2 * testRetryIvl)
		shouldCall = false
		strgErr = assert.AnError
		err = db.Refresh(ctx)
		assert.NoError(t, err)
		assertCertificatePair(t, wantCertPath, wantKeyPath)
	}))

	disableCtx := testutil.ContextWithTimeout(t, testTimeout)
	db.AddCertificate(disableCtx, testProfileID, testDomains, testStateDisabled)
	require.NoFileExists(t, wantCertPath)
	require.NoFileExists(t, wantKeyPath)

	require.True(t, t.Run("not_found", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testProfileID, testDomains, testStateOK)

		shouldCall = true
		strgErr = tlsconfig.ErrCertificateNotFound
		ctx = testutil.ContextWithTimeout(t, testTimeout)
		err := db.Refresh(ctx)
		assert.Error(t, err)
		assert.NoFileExists(t, wantCertPath)
		assert.NoFileExists(t, wantKeyPath)

		now = now.Add(testRetryIvl)
		shouldCall = false
		ctx = testutil.ContextWithTimeout(t, testTimeout)
		err = db.Refresh(ctx)
		assert.NoError(t, err)
		assert.NoFileExists(t, wantCertPath)
		assert.NoFileExists(t, wantKeyPath)
	}))
}

func TestCustomDomainDB_Refresh_present(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	wantCertPath, wantKeyPath := newCertAndKeyPaths(cacheDir)

	certDER, rsaKey := newCertAndKey(t, 1)
	writeCertAndKey(t, certDER, wantCertPath, rsaKey, wantKeyPath)

	conf := &tlsconfig.CustomDomainDBConfig{
		Storage: &testCustomDomainStorage{
			onCertificateData: func(
				ctx context.Context,
				certName agd.CertificateName,
			) (cert, key []byte, err error) {
				assert.Equal(t, testCertName, certName)

				return certDER, x509.MarshalPKCS1PrivateKey(rsaKey), nil
			},
		},
		CacheDirPath: cacheDir,
	}

	require.True(t, t.Run("both_present", func(t *testing.T) {
		db := newCustomDomainDB(t, conf)

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testProfileID, testDomains, testStateOK)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		err := db.Refresh(ctx)
		require.NoError(t, err)

		assertCustomDomainMatch(t, db, testDomain, true)
		assertCertificatePair(t, wantCertPath, wantKeyPath)
	}))

	require.True(t, t.Run("cert_present", func(t *testing.T) {
		err := os.Remove(wantKeyPath)
		require.NoError(t, err)

		db := newCustomDomainDB(t, conf)

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testProfileID, testDomains, testStateOK)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		err = db.Refresh(ctx)
		require.NoError(t, err)

		assertCustomDomainMatch(t, db, testDomain, true)
		assertCertificatePair(t, wantCertPath, wantKeyPath)
	}))
}

func BenchmarkCustomDomainDB_Match(b *testing.B) {
	db := newCustomDomainDB(b, nil)

	severalTestDomains := []string{
		"domain.examples",
		"*.domain.examples",
		"*.wildcard.examples",
	}
	profIDs := []agd.ProfileID{
		errors.Must(agd.NewProfileID("example1")),
		errors.Must(agd.NewProfileID("example2")),
		errors.Must(agd.NewProfileID("example3")),
		errors.Must(agd.NewProfileID("example4")),
		errors.Must(agd.NewProfileID("example5")),
	}

	addCtx := testutil.ContextWithTimeout(b, testTimeout)
	db.AddCertificate(addCtx, testProfileID, testDomains, testStateOK)

	for _, profID := range profIDs {
		db.AddCertificate(addCtx, profID, severalTestDomains, testStateOK)
	}

	ctx := context.Background()

	b.Run("domain", func(b *testing.B) {
		var matched string

		b.ReportAllocs()
		for b.Loop() {
			matched, _ = db.Match(ctx, testDomain)
		}

		require.Equal(b, testDomain, matched)
	})

	b.Run("several_domains", func(b *testing.B) {
		var matched string

		b.ReportAllocs()
		for b.Loop() {
			matched, _ = db.Match(ctx, severalTestDomains[0])
		}

		require.Equal(b, severalTestDomains[0], matched)
	})

	b.Run("wildcard", func(b *testing.B) {
		var matched string

		b.ReportAllocs()
		for b.Loop() {
			matched, _ = db.Match(ctx, testDomainWildcard)
		}

		require.Equal(b, testWildcard, matched)
	})

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig
	//	cpu: Apple M4 Pro
	//  BenchmarkCustomDomainDB_Match/domain-14             11747257    92.90 ns/op 	16 B/op     1 allocs/op
	//	BenchmarkCustomDomainDB_Match/several_domains-14	5873468		203.9 ns/op		240 B/op	4 allocs/op
	//  BenchmarkCustomDomainDB_Match/wildcard-14           12270618    98.75 ns/op 	16 B/op     1 allocs/op
}
