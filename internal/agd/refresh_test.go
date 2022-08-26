package agd_test

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshWorker(t *testing.T) {
	// Test Constants

	const (
		testIvl                  = 5 * time.Millisecond
		testIvlLong              = 1 * time.Hour
		name                     = "test refresher"
		testError   errors.Error = "test error"
	)

	// Test Mocks

	pt := testutil.PanicT{}
	refreshSync := make(chan agdtest.Signal, 1)

	refr := &agdtest.Refresher{
		OnRefresh: func(_ context.Context) (err error) {
			agdtest.RequireSend(pt, refreshSync, testTimeout)

			return nil
		},
	}

	errRefr := &agdtest.Refresher{
		OnRefresh: func(_ context.Context) (err error) {
			agdtest.RequireSend(pt, refreshSync, testTimeout)

			return testError
		},
	}

	errCh := make(chan agdtest.Signal, 1)
	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, _ error) {
			agdtest.RequireSend(pt, errCh, testTimeout)
		},
	}

	// Test Helpers

	refrConf := func(
		refr agd.Refresher,
		ivl time.Duration,
		refrOnShutDown bool,
	) (conf *agd.RefreshWorkerConfig) {
		return &agd.RefreshWorkerConfig{
			Context: func() (ctx context.Context, cancel context.CancelFunc) {
				return context.WithTimeout(context.Background(), testTimeout)
			},
			Refresher:           refr,
			ErrColl:             errColl,
			Name:                name,
			Interval:            ivl,
			RefreshOnShutdown:   refrOnShutDown,
			RoutineLogsAreDebug: false,
		}
	}

	// Tests

	t.Run("success", func(t *testing.T) {
		w := agd.NewRefreshWorker(refrConf(refr, testIvl, false))

		err := w.Start()
		require.NoError(t, err)

		agdtest.RequireReceive(pt, refreshSync, testTimeout)
		require.Empty(t, errCh)

		shutdown, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		err = w.Shutdown(shutdown)
		require.NoError(t, err)
	})

	t.Run("success_on_shutdown", func(t *testing.T) {
		w := agd.NewRefreshWorker(refrConf(refr, testIvlLong, true))

		err := w.Start()
		require.NoError(t, err)

		shutdown, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		err = w.Shutdown(shutdown)
		require.NoError(t, err)

		agdtest.RequireReceive(pt, refreshSync, testTimeout)
		require.Empty(t, errCh)
	})

	t.Run("error", func(t *testing.T) {
		w := agd.NewRefreshWorker(refrConf(errRefr, testIvl, false))

		err := w.Start()
		require.NoError(t, err)

		agdtest.RequireReceive(pt, refreshSync, testTimeout)
		agdtest.RequireReceive(pt, errCh, testTimeout)

		shutdown, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		err = w.Shutdown(shutdown)
		require.NoError(t, err)
	})

	t.Run("error_on_shutdown", func(t *testing.T) {
		w := agd.NewRefreshWorker(refrConf(errRefr, testIvlLong, true))

		err := w.Start()
		require.NoError(t, err)

		shutdown, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		err = w.Shutdown(shutdown)
		assert.ErrorIs(t, err, testError)

		agdtest.RequireReceive(pt, refreshSync, testTimeout)
		require.Empty(t, errCh)
	})
}
