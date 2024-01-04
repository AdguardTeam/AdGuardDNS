package agdservice_test

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/golibs/errors"
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

// newRefrConf returns worker configuration.
func newRefrConf(
	t *testing.T,
	refr agdservice.Refresher,
	ivl time.Duration,
	refrOnShutDown bool,
	errCh chan sig,
) (conf *agdservice.RefreshWorkerConfig) {
	t.Helper()

	pt := testutil.PanicT{}

	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, _ error) {
			testutil.RequireSend(pt, errCh, sig{}, testTimeout)
		},
	}

	return &agdservice.RefreshWorkerConfig{
		Context: func() (ctx context.Context, cancel context.CancelFunc) {
			return context.WithTimeout(context.Background(), testTimeout)
		},
		Refresher:           refr,
		ErrColl:             errColl,
		Name:                name,
		Interval:            ivl,
		RefreshOnShutdown:   refrOnShutDown,
		RoutineLogsAreDebug: false,
		RandomizeStart:      false,
	}
}

func TestRefreshWorker(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		refr, syncCh := newTestRefresher(t, nil)
		errCh := make(chan sig, 1)

		w := agdservice.NewRefreshWorker(newRefrConf(t, refr, testIvl, false, errCh))

		err := w.Start(agdtest.ContextWithTimeout(t, testTimeout))
		require.NoError(t, err)

		testutil.RequireReceive(t, syncCh, testTimeout)
		require.Empty(t, errCh)

		err = w.Shutdown(agdtest.ContextWithTimeout(t, testTimeout))
		require.NoError(t, err)
	})

	t.Run("success_on_shutdown", func(t *testing.T) {
		refr, syncCh := newTestRefresher(t, nil)
		errCh := make(chan sig, 1)

		w := agdservice.NewRefreshWorker(newRefrConf(t, refr, testIvlLong, true, errCh))

		err := w.Start(agdtest.ContextWithTimeout(t, testTimeout))
		require.NoError(t, err)

		err = w.Shutdown(agdtest.ContextWithTimeout(t, testTimeout))
		require.NoError(t, err)

		testutil.RequireReceive(t, syncCh, testTimeout)
		require.Empty(t, errCh)
	})

	t.Run("error", func(t *testing.T) {
		errRefr, syncCh := newTestRefresher(t, testError)
		errCh := make(chan sig, 1)

		w := agdservice.NewRefreshWorker(newRefrConf(t, errRefr, testIvl, false, errCh))

		err := w.Start(agdtest.ContextWithTimeout(t, testTimeout))
		require.NoError(t, err)

		testutil.RequireReceive(t, syncCh, testTimeout)
		testutil.RequireReceive(t, errCh, testTimeout)

		err = w.Shutdown(agdtest.ContextWithTimeout(t, testTimeout))
		require.NoError(t, err)
	})

	t.Run("error_on_shutdown", func(t *testing.T) {
		errRefr, syncCh := newTestRefresher(t, testError)
		errCh := make(chan sig, 1)

		w := agdservice.NewRefreshWorker(newRefrConf(t, errRefr, testIvlLong, true, errCh))

		err := w.Start(agdtest.ContextWithTimeout(t, testTimeout))
		require.NoError(t, err)

		err = w.Shutdown(agdtest.ContextWithTimeout(t, testTimeout))
		assert.ErrorIs(t, err, testError)

		testutil.RequireReceive(t, syncCh, testTimeout)
		require.Empty(t, errCh)
	})
}
