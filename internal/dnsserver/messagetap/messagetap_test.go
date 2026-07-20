package messagetap_test

import (
	"context"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/messagetap"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// testTimeout is the common timeout for tests.
const testTimeout = 1 * time.Second

// testLogger is the common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

// testTapper is a test implementation of the [messagetap.Tapper] interface.
type testTapper struct {
	OnTap      func(ctx context.Context, payload []byte)
	OnStart    func(ctx context.Context) (err error)
	OnShutdown func(ctx context.Context) (err error)
}

// type check
var _ messagetap.Tapper = (*testTapper)(nil)

// Tap implements the [messagetap.Tapper] interface for *testTapper.
func (t *testTapper) Tap(ctx context.Context, payload []byte) {
	t.OnTap(ctx, payload)
}

// Start implements the [service.Interface] interface for *testTapper.
func (t *testTapper) Start(ctx context.Context) (err error) {
	return t.OnStart(ctx)
}

// Shutdown implements the [service.Interface] interface for *testTapper.
func (t *testTapper) Shutdown(ctx context.Context) (err error) {
	return t.OnShutdown(ctx)
}
