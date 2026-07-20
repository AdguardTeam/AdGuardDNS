package agdruntime_test

import (
	"sync/atomic"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdruntime"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefresher_Refresh(t *testing.T) {
	t.Parallel()

	const (
		before = 110
		limit  = 100
	)

	var numTerminated atomic.Uint32

	m := &testManager{
		onTerminateThread: func() {
			numTerminated.Add(1)
		},
		onThreadsCount: func() (count uint) {
			return before
		},
	}

	r := agdruntime.NewRefresher(&agdruntime.RefresherConfig{
		Logger:  testLogger,
		Manager: m,
		Limit:   limit,
	})

	err := r.Refresh(testutil.ContextWithTimeout(t, testTimeout))
	require.NoError(t, err)

	assert.Equal(t, uint32(before-limit), numTerminated.Load())
}
