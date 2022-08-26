package agdtest

import (
	"time"

	"github.com/stretchr/testify/require"
)

// Synchronization Utilities
//
// TODO(a.garipov): Add generic versions when we can.
//
// TODO(a.garipov): Add to golibs once the API is stabilized.

// Signal is a simple signal type alias for tests.
type Signal = struct{}

// RequireSend waits until a signal is sent to ch or until the timeout is
// reached.  If the timeout is reached, the test is failed.
func RequireSend(t require.TestingT, ch chan<- Signal, timeout time.Duration) {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case ch <- Signal{}:
		// Go on.
	case <-timer.C:
		t.Errorf("did not send after %s", timeout)
		t.FailNow()
	}
}

// RequireReceive waits until a signal is received from ch or until the timeout
// is reached.  If the timeout is reached, the test is failed.
func RequireReceive(t require.TestingT, ch <-chan Signal, timeout time.Duration) {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ch:
		// Go on.
	case <-timer.C:
		t.Errorf("did not receive after %s", timeout)
		t.FailNow()
	}
}
