package dnsserver_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/testutil"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// testTimeout is a common timeout for tests.
const testTimeout = dnsserver.DefaultReadTimeout
