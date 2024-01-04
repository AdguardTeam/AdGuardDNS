package agdservice_test

import (
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// testTimeout is the timeout for common test operations.
const testTimeout = 1 * time.Second
