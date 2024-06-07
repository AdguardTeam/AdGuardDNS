package rulestat_test

import (
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// testTimeout is the common timeout for tests.
const testTimeout = 1 * time.Second
