package tlsconfig_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/faketime"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testWellKnownPath is the well-known certificate validation path for tests.
const testWellKnownPath = "/.well-known/pki-validation/abcd1234"

func TestCustomDomain_IsValidWellKnownRequest(t *testing.T) {
	t.Parallel()

	db := tlsconfig.NewCustomDomainDB(&tlsconfig.CustomDomainDBConfig{
		Logger:  testLogger,
		Clock:   timeutil.SystemClock{},
		ErrColl: agdtest.NewErrorCollector(),
		Storage: tlsconfig.EmptyCustomDomainStorage{},
		// TODO(a.garipov):  Add more once more fields appear.
	})

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

func TestCustomDomain_IsValidWellKnownRequest_expiredLater(t *testing.T) {
	t.Parallel()

	var (
		expire     = time.Now()
		nowEarlier = expire.Add(-1 * time.Hour)
		nowLater   = expire.Add(1 * time.Hour)
	)

	nowCh := make(chan time.Time, 1)
	clock := &faketime.Clock{
		OnNow: func() (now time.Time) {
			now, ok := testutil.RequireReceive(t, nowCh, testTimeout)
			require.True(t, ok)

			return now
		},
	}

	db := tlsconfig.NewCustomDomainDB(&tlsconfig.CustomDomainDBConfig{
		Logger:  testLogger,
		Clock:   clock,
		ErrColl: agdtest.NewErrorCollector(),
		Storage: tlsconfig.EmptyCustomDomainStorage{},
		// TODO(a.garipov):  Add more once more fields appear.
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
