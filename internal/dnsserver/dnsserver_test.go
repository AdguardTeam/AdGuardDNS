package dnsserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/testutil"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// testTimeout is a common timeout for tests.
const testTimeout = dnsserver.DefaultReadTimeout

// contextWithTimeout is a helper that creates a new context with timeout and
// registers ctx's cleanup with t.Cleanup.
//
// TODO(a.garipov): Move to golibs and DRY.
func contextWithTimeout(tb testing.TB, timeout time.Duration) (ctx context.Context) {
	tb.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	tb.Cleanup(cancel)

	return ctx
}
