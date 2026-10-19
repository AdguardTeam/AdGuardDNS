package tlsconfig_test

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/faketime"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// testAccountID is the common account ID for tests.
	testAccountID agd.AccountID = 123

	// testWellKnownPath is the well-known certificate validation path for tests.
	testWellKnownPath = "/.well-known/pki-validation/abcd1234"

	testAccountIPDomain = "account.ip.example"

	// testRetryIvl is the retry interval for tests.
	testRetryIvl = 1 * time.Minute
)

// testAccountIP is a common account IP value for tests.
var testAccountIP = netip.MustParseAddr("192.0.2.0")

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

// testBindPrefixes are the common bind prefixes for tests.
var testBindPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.1/32"),
	netip.MustParsePrefix("::1/128"),
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
		CertName:  testCustomCertName,
		Enabled:   false,
	}

	testStateExpired = &agd.CustomDomainStateCurrent{
		NotBefore: testTimeExpired.Add(-1 * timeutil.Day),
		NotAfter:  testTimeExpired,
		CertName:  testCustomCertName,
		Enabled:   true,
	}

	testStateFuture = &agd.CustomDomainStateCurrent{
		NotBefore: testTimeFuture.Add(-1 * timeutil.Day),
		NotAfter:  testTimeFuture,
		CertName:  testCustomCertName,
		Enabled:   true,
	}

	testStateOK = &agd.CustomDomainStateCurrent{
		NotBefore: testTimeNow.Add(-1 * timeutil.Day),
		NotAfter:  testTimeNow.Add(1 * timeutil.Day),
		CertName:  testCustomCertName,
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
	c.ErrColl = cmp.Or[errcoll.Interface](c.ErrColl, testErrColl)
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
		ok := db.IsValidWellKnownRequest(ctx, httpReq, netip.Addr{})
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
		ok := db.IsValidWellKnownRequest(ctx, httpReq, netip.Addr{})
		assert.True(t, ok)

		// Now expire it.
		s = &agd.CustomDomainStatePending{
			Expire:        time.Now().Add(-1 * time.Hour),
			WellKnownPath: testWellKnownPath,
		}

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		db.SetWellKnownPath(ctx, s)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		ok = db.IsValidWellKnownRequest(ctx, httpReq, netip.Addr{})
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
		ok := db.IsValidWellKnownRequest(ctx, httpReq, netip.Addr{})
		require.True(t, ok)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		postReq := httpReq.Clone(ctx)
		postReq.Method = http.MethodPost

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		ok = db.IsValidWellKnownRequest(ctx, postReq, netip.Addr{})
		assert.False(t, ok)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		tlsReq := httpReq.Clone(ctx)
		tlsReq.TLS = &tls.ConnectionState{}

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		ok = db.IsValidWellKnownRequest(ctx, tlsReq, netip.Addr{})
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
		ok := db.IsValidWellKnownRequest(ctx, httpReq, netip.Addr{})
		require.True(t, ok)

		// Now delete all.
		ctx = testutil.ContextWithTimeout(t, testTimeout)
		db.DeleteAllWellKnownPaths(ctx)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		ok = db.IsValidWellKnownRequest(ctx, httpReq, netip.Addr{})
		assert.False(t, ok)
	}))
}

func TestCustomDomainDB_IsValidWellKnownRequest_accountIP(t *testing.T) {
	t.Parallel()

	clock := &faketime.Clock{
		OnNow: func() (now time.Time) { return testTimeNow },
	}

	db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
		Clock: clock,
	})

	accountIPs := []*agd.AccountIP{{
		Enabled: true,
		Address: testAccountIP,
		Domains: []*agd.CustomDomainConfig{{
			State: &agd.CustomDomainStatePending{
				Expire:        testTimeNow.Add(1 * time.Hour),
				WellKnownPath: testWellKnownPath,
			},
			Domains: []string{testAccountIPDomain},
		}},
	}}

	addCtx := testutil.ContextWithTimeout(t, testTimeout)
	db.AddAccountIPCertificates(addCtx, testAccountID, accountIPs)

	t.Run("matching_laddr", func(t *testing.T) {
		t.Parallel()

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testWellKnownPath, nil)
		require.NoError(t, err)

		got := db.IsValidWellKnownRequest(ctx, req, testAccountIP)
		require.True(t, got)
	})

	t.Run("not_matching_laddr", func(t *testing.T) {
		t.Parallel()

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testWellKnownPath, nil)
		require.NoError(t, err)

		addr := netip.MustParseAddr("192.0.2.1")
		got := db.IsValidWellKnownRequest(ctx, req, addr)
		require.False(t, got)
	})
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
	ok := db.IsValidWellKnownRequest(ctx, httpReq, netip.Addr{})
	require.True(t, ok)

	nowCh <- nowLater
	ctx = testutil.ContextWithTimeout(t, testTimeout)
	ok = db.IsValidWellKnownRequest(ctx, httpReq, netip.Addr{})
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
				Clock:        clock,
				BindPrefixes: testBindPrefixes,
			})

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			db.AddCertificate(ctx, testAccountID, testDomains, tc.state)

			assertCustomDomainMatch(t, db, testDomain, netip.Addr{}, tc.wantMatch)
		})
	}
}

// assertCustomDomainMatch is a helper function for checking the result of a
// match.
func assertCustomDomainMatch(
	tb testing.TB,
	db *tlsconfig.CustomDomainDB,
	cliSrvName string,
	wantAccIP netip.Addr,
	wantMatch bool,
) {
	tb.Helper()

	ctx := testutil.ContextWithTimeout(tb, testTimeout)
	matched, accID, accIP := db.Match(ctx, cliSrvName)
	if wantMatch {
		assert.Equal(tb, cliSrvName, matched)
		assert.Equal(tb, testAccountID, accID)
		assert.Equal(tb, wantAccIP, accIP)
	} else {
		assert.Empty(tb, matched)
		assert.Zero(tb, accID)
		assert.Zero(tb, accIP)
	}
}

func TestCustomDomainDB_AddAccountIPCertificates(t *testing.T) {
	t.Parallel()

	clock := &faketime.Clock{
		OnNow: func() (now time.Time) { return testTimeNow },
	}

	testCases := []struct {
		ip        *agd.AccountIP
		name      string
		wantMatch bool
	}{{
		ip: &agd.AccountIP{
			Address: testAccountIP,
			Enabled: true,
			Domains: []*agd.CustomDomainConfig{{
				State:   testStateOK,
				Domains: testDomains,
			}},
		},
		name:      "good",
		wantMatch: true,
	}, {
		ip: &agd.AccountIP{
			Address: testAccountIP,
			Enabled: true,
			Domains: []*agd.CustomDomainConfig{{
				State:   testStateExpired,
				Domains: testDomains,
			}},
		},
		name:      "expired",
		wantMatch: false,
	}, {
		ip: &agd.AccountIP{
			Address: testAccountIP,
			Enabled: false,
			Domains: []*agd.CustomDomainConfig{{
				State:   testStateOK,
				Domains: testDomains,
			}},
		},
		name:      "disabled",
		wantMatch: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
				Clock:        clock,
				BindPrefixes: testBindPrefixes,
			})

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			db.AddAccountIPCertificates(ctx, testAccountID, []*agd.AccountIP{tc.ip})

			assertCustomDomainMatch(t, db, testDomain, testAccountIP, tc.wantMatch)
		})
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
		db.AddCertificate(ctx, testAccountID, testDomains, testStateOK)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testAccountID, testDomains, testStateOK)

		assertCustomDomainMatch(t, db, testDomain, netip.Addr{}, true)
	})

	t.Run("disabled", func(t *testing.T) {
		t.Parallel()

		db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
			Clock: clock,
		})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testAccountID, testDomains, testStateOK)

		assertCustomDomainMatch(t, db, testDomain, netip.Addr{}, true)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testAccountID, testDomains, testStateDisabled)

		assertCustomDomainMatch(t, db, testDomain, netip.Addr{}, false)
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
		db.AddCertificate(ctx, testAccountID, testDomains, testStateExpired)

		assertCustomDomainMatch(t, db, testDomain, netip.Addr{}, true)

		now = testTimeNow

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testAccountID, testDomains, testStateExpired)

		assertCustomDomainMatch(t, db, testDomain, netip.Addr{}, false)
	})
}

func TestCustomDomainDB_CertFiles(t *testing.T) {
	t.Parallel()

	clock := &faketime.Clock{
		OnNow: func() (now time.Time) { return testTimeNow },
	}

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
			Clock: clock,
		})

		certFiles := db.CertFiles()
		assert.NotNil(t, certFiles)
		assert.Equal(t, 0, certFiles.Len())
	})

	t.Run("list", func(t *testing.T) {
		t.Parallel()

		const otherCertName = "other"

		cacheDir := t.TempDir()

		db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
			Clock:        clock,
			CacheDirPath: cacheDir,
		})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testAccountID, testDomains, testStateOK)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testAccountID, testDomains, &agd.CustomDomainStateCurrent{
			NotBefore: testTimeNow.Add(-1 * timeutil.Day),
			NotAfter:  testTimeNow.Add(1 * timeutil.Day),
			CertName:  otherCertName,
			Enabled:   true,
		})

		certFiles := db.CertFiles()
		assert.Equal(t, container.NewSortedSliceSet(
			string(testCustomCertName)+tlsconfig.CustomDomainCertExt,
			string(testCustomCertName)+tlsconfig.CustomDomainKeyExt,
			string(otherCertName)+tlsconfig.CustomDomainCertExt,
			string(otherCertName)+tlsconfig.CustomDomainKeyExt,
		), certFiles)
	})
}

func TestCustomDomainDB_Match(t *testing.T) {
	t.Parallel()

	db := newCustomDomainDB(t, nil)

	accountIPState := *testStateOK
	accountIPState.CertName = agd.CertificateName(testAccountIPDomain)

	accountIPs := []*agd.AccountIP{{
		Enabled: true,
		Address: testAccountIP,
		Domains: []*agd.CustomDomainConfig{{
			State:   &accountIPState,
			Domains: []string{testAccountIPDomain},
		}},
	}}

	addCtx := testutil.ContextWithTimeout(t, testTimeout)
	db.AddCertificate(addCtx, testAccountID, testDomains, testStateOK)
	db.AddAccountIPCertificates(addCtx, testAccountID, accountIPs)

	testCases := []struct {
		wantAccIP   netip.Addr
		name        string
		cliSrvName  string
		wantMatched string
		wantAccID   agd.AccountID
	}{{
		name:        "match_domain",
		cliSrvName:  testDomain,
		wantMatched: testDomain,
		wantAccID:   testAccountID,
		wantAccIP:   netip.Addr{},
	}, {
		name:        "match_wildcard",
		cliSrvName:  testDomainWildcard,
		wantMatched: testWildcard,
		wantAccID:   testAccountID,
		wantAccIP:   netip.Addr{},
	}, {
		name:        "no_match",
		cliSrvName:  "other.example",
		wantMatched: "",
		wantAccID:   0,
		wantAccIP:   netip.Addr{},
	}, {
		name:        "no_match_wildcard_suf",
		cliSrvName:  testDomainWildcardTop,
		wantMatched: "",
		wantAccID:   0,
		wantAccIP:   netip.Addr{},
	}, {
		name:        "account_ip",
		cliSrvName:  testAccountIPDomain,
		wantMatched: testAccountIPDomain,
		wantAccID:   testAccountID,
		wantAccIP:   testAccountIP,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			matched, accID, accIP := db.Match(ctx, tc.cliSrvName)
			assert.Equal(t, tc.wantMatched, matched)
			assert.Equal(t, tc.wantAccID, accID)
			assert.Equal(t, tc.wantAccIP, accIP)
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
	db.AddCertificate(addCtx, testAccountID, testDomains, testStateOK)

	futureState := &agd.CustomDomainStateCurrent{}
	*futureState = *testStateFuture
	futureState.CertName = futureState.CertName + "_future"

	addCtx = testutil.ContextWithTimeout(t, testTimeout)
	db.AddCertificate(addCtx, testAccountID, testDomains, futureState)

	assertCustomDomainMatch(t, db, testDomain, netip.Addr{}, true)

	now = testTimeFuture

	assertCustomDomainMatch(t, db, testDomain, netip.Addr{}, true)
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
	onAdd  func(ctx context.Context, params *tlsconfig.AddParams) (err error)
	onBind func(
		ctx context.Context,
		name agd.CertificateName,
		pref netip.Prefix,
	) (err error)
	onClone            func() (c *tls.Config)
	onCloneWithMetrics func(proto, srvName string, deviceDomains []string) (c *tls.Config)
	onRemove           func(ctx context.Context, name agd.CertificateName) (err error)
}

// type check
var _ tlsconfig.Manager = (*testManager)(nil)

// Add implements the [tlsconfig.Manager] interface for *testManager.
func (m *testManager) Add(ctx context.Context, params *tlsconfig.AddParams) (err error) {
	return m.onAdd(ctx, params)
}

// Bind implements the [tlsconfig.Manager] interface for *testManager.
func (m *testManager) Bind(
	ctx context.Context,
	name agd.CertificateName,
	pref netip.Prefix,
) (err error) {
	return m.onBind(ctx, name, pref)
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
func (m *testManager) Remove(ctx context.Context, name agd.CertificateName) (err error) {
	return m.onRemove(ctx, name)
}

// newTestManager returns a new *testManager all methods of which panic.
func newTestManager() (m *testManager) {
	return &testManager{
		onAdd: func(ctx context.Context, params *tlsconfig.AddParams) (err error) {
			panic(testutil.UnexpectedCall(ctx, params))
		},
		onBind: func(ctx context.Context, name agd.CertificateName, pref netip.Prefix) (err error) {
			panic(testutil.UnexpectedCall(ctx, name, pref))
		},
		onClone: func() (c *tls.Config) {
			panic(testutil.UnexpectedCall())
		},
		onCloneWithMetrics: func(proto, srvName string, deviceDomains []string) (c *tls.Config) {
			panic(testutil.UnexpectedCall(proto, srvName, deviceDomains))
		},
		onRemove: func(ctx context.Context, name agd.CertificateName) (err error) {
			panic(testutil.UnexpectedCall(ctx, name))
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
			assert.Equal(t, testCustomCertName, certName)

			certDER, rsaKey := newCertAndKey(t, 1)

			return certDER, x509.MarshalPKCS1PrivateKey(rsaKey), nil
		},
	}

	cacheDir := t.TempDir()
	wantCertPath, wantKeyPath := newCertAndKeyPaths(cacheDir, testCustomCertName)

	mgrWithAdd := newTestManager()
	mgrWithAdd.onAdd = func(ctx context.Context, params *tlsconfig.AddParams) (err error) {
		assert.Equal(t, wantCertPath, params.CertPath)
		assert.Equal(t, wantKeyPath, params.KeyPath)
		assert.True(t, params.IsCustom)

		return nil
	}
	mgrWithAdd.onBind = func(
		_ context.Context,
		n agd.CertificateName,
		p netip.Prefix,
	) (err error) {
		assert.Equal(t, testCustomCertName, n)
		assert.Contains(t, testBindPrefixes, p)

		return nil
	}

	mgrWithRemove := newTestManager()
	mgrWithRemove.onRemove = func(ctx context.Context, name agd.CertificateName) (err error) {
		assert.Equal(t, testCustomCertName, name)

		return nil
	}

	require.True(t, t.Run("success", func(t *testing.T) {
		db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
			Manager:      mgrWithAdd,
			Storage:      strg,
			CacheDirPath: cacheDir,
			BindPrefixes: testBindPrefixes,
		})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testAccountID, testDomains, testStateOK)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		err := db.Refresh(ctx)
		require.NoError(t, err)

		assertCustomDomainMatch(t, db, testDomain, netip.Addr{}, true)
		assertCertificatePair(t, wantCertPath, wantKeyPath)
	}))

	require.True(t, t.Run("success_no_update", func(t *testing.T) {
		db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
			Manager:      mgrWithAdd,
			Storage:      strg,
			CacheDirPath: cacheDir,
			BindPrefixes: testBindPrefixes,
		})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testAccountID, testDomains, testStateOK)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		err := db.Refresh(ctx)
		require.NoError(t, err)

		assertCustomDomainMatch(t, db, testDomain, netip.Addr{}, true)
		assertCertificatePair(t, wantCertPath, wantKeyPath)
	}))

	require.True(t, t.Run("expire", func(t *testing.T) {
		db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
			Manager:      mgrWithRemove,
			Storage:      strg,
			CacheDirPath: cacheDir,
			BindPrefixes: testBindPrefixes,
		})

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testAccountID, testDomains, testStateExpired)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		err := db.Refresh(ctx)
		require.NoError(t, err)

		assertCustomDomainMatch(t, db, testDomain, netip.Addr{}, false)
		assert.NoFileExists(t, wantCertPath)
		assert.NoFileExists(t, wantKeyPath)
	}))
}

// newCertAndKeyPaths is a helper that returns paths for the certificate and the
// key using the test's temporary directory.
func newCertAndKeyPaths(cacheDir string, certName agd.CertificateName) (certPath, keyPath string) {
	return filepath.Join(cacheDir, string(certName)+tlsconfig.CustomDomainCertExt),
		filepath.Join(cacheDir, string(certName)+tlsconfig.CustomDomainKeyExt)
}

func TestCustomDomainDB_Refresh_retry(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	wantCertPath, wantKeyPath := newCertAndKeyPaths(cacheDir, testCustomCertName)

	mgr := newTestManager()
	mgr.onAdd = func(ctx context.Context, params *tlsconfig.AddParams) (err error) {
		assert.Equal(t, testCustomCertName, params.Name)
		assert.Equal(t, wantCertPath, params.CertPath)
		assert.Equal(t, wantKeyPath, params.KeyPath)
		assert.True(t, params.IsCustom)

		return nil
	}
	mgr.onRemove = func(ctx context.Context, name agd.CertificateName) (err error) {
		assert.Equal(t, testCustomCertName, name)

		return nil
	}
	mgr.onBind = func(ctx context.Context, name agd.CertificateName, p netip.Prefix) (err error) {
		assert.Equal(t, testCustomCertName, name)
		assert.Contains(t, testBindPrefixes, p)

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

			assert.Equal(t, testCustomCertName, certName)

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
		BindPrefixes: testBindPrefixes,
	})

	require.True(t, t.Run("rate_limited", func(t *testing.T) {
		rlErr := &profiledb.RateLimitedError{}

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testAccountID, testDomains, testStateOK)

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
	db.AddCertificate(disableCtx, testAccountID, testDomains, testStateDisabled)
	require.NoFileExists(t, wantCertPath)
	require.NoFileExists(t, wantKeyPath)

	require.True(t, t.Run("not_found", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testAccountID, testDomains, testStateOK)

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

func TestCustomDomainDB_Refresh_stale(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()

	now := testTimeNow

	db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
		Clock: &faketime.Clock{
			OnNow: func() (n time.Time) { return now },
		},
		Storage: &testCustomDomainStorage{
			onCertificateData: func(
				ctx context.Context,
				certName agd.CertificateName,
			) (cert, key []byte, err error) {
				certDER, rsaKey := newCertAndKey(t, 1)

				return certDER, x509.MarshalPKCS1PrivateKey(rsaKey), nil
			},
		},
		CacheDirPath: cacheDir,
		BindPrefixes: testBindPrefixes,
	})

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	db.AddCertificate(ctx, testAccountID, testDomains, testStateOK)

	ctx = testutil.ContextWithTimeout(t, testTimeout)
	err := db.Refresh(ctx)
	require.NoError(t, err)

	wantCertPath, wantKeyPath := newCertAndKeyPaths(cacheDir, testCustomCertName)
	require.FileExists(t, wantCertPath)
	require.FileExists(t, wantKeyPath)

	now = testStateOK.NotAfter.Add(1 * time.Minute)

	ctx = testutil.ContextWithTimeout(t, testTimeout)
	err = db.Refresh(ctx)
	require.NoError(t, err)

	assert.NoFileExists(t, wantCertPath)
	assert.NoFileExists(t, wantKeyPath)
}

func TestCustomDomainDB_Refresh_present(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	wantCertPath, wantKeyPath := newCertAndKeyPaths(cacheDir, testCustomCertName)

	certDER, rsaKey := newCertAndKey(t, 1)
	writeCertAndKey(t, certDER, wantCertPath, rsaKey, wantKeyPath)

	conf := &tlsconfig.CustomDomainDBConfig{
		Storage: &testCustomDomainStorage{
			onCertificateData: func(
				ctx context.Context,
				certName agd.CertificateName,
			) (cert, key []byte, err error) {
				assert.Equal(t, testCustomCertName, certName)

				return certDER, x509.MarshalPKCS1PrivateKey(rsaKey), nil
			},
		},
		CacheDirPath: cacheDir,
		BindPrefixes: testBindPrefixes,
	}

	require.True(t, t.Run("both_present", func(t *testing.T) {
		db := newCustomDomainDB(t, conf)

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testAccountID, testDomains, testStateOK)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		err := db.Refresh(ctx)
		require.NoError(t, err)

		assertCustomDomainMatch(t, db, testDomain, netip.Addr{}, true)
		assertCertificatePair(t, wantCertPath, wantKeyPath)
	}))

	require.True(t, t.Run("cert_present", func(t *testing.T) {
		err := os.Remove(wantKeyPath)
		require.NoError(t, err)

		db := newCustomDomainDB(t, conf)

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testAccountID, testDomains, testStateOK)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		err = db.Refresh(ctx)
		require.NoError(t, err)

		assertCustomDomainMatch(t, db, testDomain, netip.Addr{}, true)
		assertCertificatePair(t, wantCertPath, wantKeyPath)
	}))
}

func TestCustomDomainDB_Refresh_accountIPCertificates(t *testing.T) {
	t.Parallel()

	const accountIPCertName agd.CertificateName = "account-ip-cert"
	var (
		wantCertName agd.CertificateName
		wantPrefix   netip.Prefix
		wantCertPath string
		wantKeyPath  string
	)
	mgr := newTestManager()
	mgr.onAdd = func(ctx context.Context, params *tlsconfig.AddParams) (err error) {
		assert.Equal(t, wantCertPath, params.CertPath)
		assert.Equal(t, wantKeyPath, params.KeyPath)
		assert.True(t, params.IsCustom)

		return nil
	}
	mgr.onBind = func(ctx context.Context, name agd.CertificateName, pref netip.Prefix) (err error) {
		assert.Equal(t, wantCertName, name)
		assert.Equal(t, wantPrefix, pref)

		return nil
	}

	strg := &testCustomDomainStorage{
		onCertificateData: func(
			ctx context.Context,
			certName agd.CertificateName,
		) (cert, key []byte, err error) {
			assert.Equal(t, wantCertName, certName)

			certDER, rsaKey := newCertAndKey(t, 1)

			return certDER, x509.MarshalPKCS1PrivateKey(rsaKey), nil
		},
	}

	cacheDir := t.TempDir()
	defaultBindPrefix := netip.MustParsePrefix("192.0.2.1/32")
	db := newCustomDomainDB(t, &tlsconfig.CustomDomainDBConfig{
		Storage:      strg,
		Manager:      mgr,
		CacheDirPath: cacheDir,
		BindPrefixes: []netip.Prefix{defaultBindPrefix},
	})

	require.True(t, t.Run("account_ip_cert", func(t *testing.T) {
		state := *testStateOK
		state.CertName = accountIPCertName

		accountIPDomain := "account-ip.domain.example"
		accountIPConf := []*agd.AccountIP{{
			Enabled: true,
			Address: testAccountIP,
			Domains: []*agd.CustomDomainConfig{{
				State:   &state,
				Domains: []string{accountIPDomain},
			}},
		}}

		wantCertName = accountIPCertName
		wantPrefix = netip.PrefixFrom(testAccountIP, testAccountIP.BitLen())
		wantCertPath, wantKeyPath = newCertAndKeyPaths(cacheDir, accountIPCertName)

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddAccountIPCertificates(ctx, testAccountID, accountIPConf)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		err := db.Refresh(ctx)
		require.NoError(t, err)

		assertCertificatePair(t, wantCertPath, wantKeyPath)
		assertCustomDomainMatch(t, db, accountIPDomain, testAccountIP, true)
		require.FileExists(t, wantCertPath)
		require.FileExists(t, wantKeyPath)
	}))

	require.True(t, t.Run("custom_cert", func(t *testing.T) {
		wantCertName = testCustomCertName
		wantPrefix = defaultBindPrefix
		wantCertPath, wantKeyPath = newCertAndKeyPaths(cacheDir, testCustomCertName)

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		db.AddCertificate(ctx, testAccountID, testDomains, testStateOK)

		ctx = testutil.ContextWithTimeout(t, testTimeout)
		err := db.Refresh(ctx)
		require.NoError(t, err)

		assertCertificatePair(t, wantCertPath, wantKeyPath)
		assertCustomDomainMatch(t, db, testDomain, netip.Addr{}, true)
		require.FileExists(t, wantCertPath)
		require.FileExists(t, wantKeyPath)
	}))
}

func BenchmarkCustomDomainDB_Match(b *testing.B) {
	db := newCustomDomainDB(b, nil)

	severalTestDomains := []string{
		"domain.examples",
		"*.domain.examples",
		"*.wildcard.examples",
	}
	accIDs := []agd.AccountID{
		errors.Must(agd.NewAccountID(1)),
		errors.Must(agd.NewAccountID(2)),
		errors.Must(agd.NewAccountID(3)),
		errors.Must(agd.NewAccountID(4)),
		errors.Must(agd.NewAccountID(5)),
	}

	addCtx := testutil.ContextWithTimeout(b, testTimeout)
	db.AddCertificate(addCtx, testAccountID, testDomains, testStateOK)

	for _, accID := range accIDs {
		db.AddCertificate(addCtx, accID, severalTestDomains, testStateOK)
	}

	ctx := context.Background()

	b.Run("domain", func(b *testing.B) {
		var matched string

		b.ReportAllocs()
		for b.Loop() {
			matched, _, _ = db.Match(ctx, testDomain)
		}

		require.Equal(b, testDomain, matched)
	})

	b.Run("several_domains", func(b *testing.B) {
		var matched string

		b.ReportAllocs()
		for b.Loop() {
			matched, _, _ = db.Match(ctx, severalTestDomains[0])
		}

		require.Equal(b, severalTestDomains[0], matched)
	})

	b.Run("wildcard", func(b *testing.B) {
		var matched string

		b.ReportAllocs()
		for b.Loop() {
			matched, _, _ = db.Match(ctx, testDomainWildcard)
		}

		require.Equal(b, testWildcard, matched)
	})

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig
	//	cpu: Apple M4 Pro
	//	BenchmarkCustomDomainDB_Match/domain-14         	13683159	        73.28 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkCustomDomainDB_Match/several_domains-14         	16964437	        72.20 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkCustomDomainDB_Match/wildcard-14                	14731984	        78.37 ns/op	       0 B/op	       0 allocs/op
}
