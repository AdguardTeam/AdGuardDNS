package billstat_test

import (
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
)

// Common Constants And Utilities

func TestMain(m *testing.M) {
	agdtest.DiscardLogOutput(m)
}

// testTimeout is the timeout for common test operations.
const testTimeout = 1 * time.Second
