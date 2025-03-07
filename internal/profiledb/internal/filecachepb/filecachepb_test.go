package filecachepb_test

import (
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// testTimeout is the common timeout for tests.
const testTimeout = 1 * time.Second

// testLogger is the common logger for tests.
var testLogger = slogutil.NewDiscardLogger()
