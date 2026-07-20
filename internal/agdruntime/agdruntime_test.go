package agdruntime_test

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdruntime"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is the common timeout for tests and contexts.
const testTimeout = 1 * time.Second

// testLogger is the common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

// testManager is a test implementation of the [agdruntime.Manager] interface.
type testManager struct {
	onTerminateThread func()
	onThreadsCount    func() (count uint)
}

// type check
var _ agdruntime.Manager = (*testManager)(nil)

// TerminateThread implements the [agdruntime.Manager] interface for
// *testManager.
func (t *testManager) TerminateThread() {
	t.onTerminateThread()
}

// ThreadsCount implements the [agdruntime.Manager] interface for *testManager.
func (t *testManager) ThreadsCount() (count uint) {
	return t.onThreadsCount()
}

func TestSystem(t *testing.T) {
	t.Parallel()

	const goroutinesCount = 100

	d := agdruntime.System{}

	before := d.ThreadsCount()
	require.Positive(t, before)

	unlock := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(goroutinesCount)

	// Spawn goroutines.
	for range goroutinesCount {
		go func() {
			// Lock goroutine to OS thread and block it, so the Go runtime is
			// forced to create a new thread.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			wg.Done()

			<-unlock
		}()
	}

	// Wait for goroutines to get ready.
	wg.Wait()

	// Unlock threads.
	close(unlock)

	inTest := d.ThreadsCount()
	require.GreaterOrEqual(t, inTest, before)

	// Terminate threads.
	for range goroutinesCount {
		done := make(chan struct{})
		go func() {
			defer close(done)

			d.TerminateThread()
		}()

		<-done
	}

	after := d.ThreadsCount()
	require.Positive(t, after)

	assert.Less(t, after, inTest)
	assert.InEpsilon(t, after, before, 0.5)
}
