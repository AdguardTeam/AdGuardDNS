package agd_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/testutil"
)

// Common Constants And Utilities

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// testTimeout is the timeout for common test operations.
const testTimeout = 1 * time.Second

// testProfID is the profile ID for tests.
const testProfID agd.ProfileID = "prof1234"

// testDevID is the device ID for tests.
const testDevID agd.DeviceID = "dev1234"

// testClientIPv4 is the client IP for tests
var testClientIPv4 = netip.AddrFrom4([4]byte{1, 2, 3, 4})
