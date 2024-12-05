package agdservice_test

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sig is a convenient alias for struct{} when it's used as a signal for
// synchronization.
type sig = struct{}

const (
	testIvl                  = 5 * time.Millisecond
	testIvlLong              = 1 * time.Hour
	name                     = "test refresher"
	testError   errors.Error = "test error"
)

// newTestRefresher is a helper that returns refr and linked syncCh channel.
func newTestRefresher(t *testing.T, respErr error) (refr *agdtest.Refresher, syncCh chan sig) {
	t.Helper()

	pt := testutil.PanicT{}

	syncCh = make(chan sig, 1)
	refr = &agdtest.Refresher{
		OnRefresh: func(_ context.Context) (err error) {
			testutil.RequireSend(pt, syncCh, sig{}, testTimeout)

			return respErr
		},
	}

	return refr, syncCh
}

// newRefrConfig returns worker configuration.
func newRefrConfig(
	t *testing.T,
	refr agdservice.Refresher,
	ivl time.Duration,
	refrOnShutDown bool,
) (conf *agdservice.RefreshWorkerConfig) {
	t.Helper()

	return &agdservice.RefreshWorkerConfig{
		Context: func() (ctx context.Context, cancel context.CancelFunc) {
			return context.WithTimeout(context.Background(), testTimeout)
		},
		Logger:            slogutil.NewDiscardLogger(),
		Refresher:         refr,
		Interval:          ivl,
		RefreshOnShutdown: refrOnShutDown,
		RandomizeStart:    false,
	}
}

func TestRefreshWorker(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		refr, syncCh := newTestRefresher(t, nil)

		w := agdservice.NewRefreshWorker(newRefrConfig(t, refr, testIvl, false))

		err := w.Start(testutil.ContextWithTimeout(t, testTimeout))
		require.NoError(t, err)

		testutil.RequireReceive(t, syncCh, testTimeout)

		err = w.Shutdown(testutil.ContextWithTimeout(t, testTimeout))
		require.NoError(t, err)
	})

	t.Run("success_on_shutdown", func(t *testing.T) {
		refr, syncCh := newTestRefresher(t, nil)
		errCh := make(chan sig, 1)

		w := agdservice.NewRefreshWorker(newRefrConfig(t, refr, testIvlLong, true))

		err := w.Start(testutil.ContextWithTimeout(t, testTimeout))
		require.NoError(t, err)

		err = w.Shutdown(testutil.ContextWithTimeout(t, testTimeout))
		require.NoError(t, err)

		testutil.RequireReceive(t, syncCh, testTimeout)
		require.Empty(t, errCh)
	})

	t.Run("error", func(t *testing.T) {
		refrWithError, syncCh := newTestRefresher(t, testError)

		w := agdservice.NewRefreshWorker(newRefrConfig(t, refrWithError, testIvl, false))

		err := w.Start(testutil.ContextWithTimeout(t, testTimeout))
		require.NoError(t, err)

		testutil.RequireReceive(t, syncCh, testTimeout)

		err = w.Shutdown(testutil.ContextWithTimeout(t, testTimeout))
		require.NoError(t, err)
	})

	t.Run("error_on_shutdown", func(t *testing.T) {
		refrWithError, syncCh := newTestRefresher(t, testError)

		w := agdservice.NewRefreshWorker(newRefrConfig(t, refrWithError, testIvlLong, true))

		err := w.Start(testutil.ContextWithTimeout(t, testTimeout))
		require.NoError(t, err)

		err = w.Shutdown(testutil.ContextWithTimeout(t, testTimeout))
		assert.ErrorIs(t, err, testError)

		testutil.RequireReceive(t, syncCh, testTimeout)
	})
}
