package bindtodevice_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/golibs/testutil"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// Common interface listener IDs for tests
const (
	testID1 bindtodevice.ID = "id1"
	testID2 bindtodevice.ID = "id2"
)

// Common port numbers for tests.
//
// TODO(a.garipov): Figure a way to use 0 in most real tests.
const (
	testPort1 uint16 = 12345
	testPort2 uint16 = 12346
)

// testIfaceName is the common network interface name for tests.
const testIfaceName = "not_a_real_iface0"

// testSubnetIPv4 is a common subnet for tests.
var testSubnetIPv4 = netip.MustParsePrefix("1.2.3.0/24")
