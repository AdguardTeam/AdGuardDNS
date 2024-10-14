package backendpb

import (
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/c2h5oh/datasize"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// Common IDs for tests and their string forms.
//
// TODO(a.garipov):  Move all or most tests into external and unexport these.
const (
	TestDeviceIDStr     = "dev1234"
	TestHumanIDStr      = "My-Device-X--10"
	TestHumanIDLowerStr = "my-device-x--10"
	TestProfileIDStr    = "prof1234"

	TestDeviceID     agd.DeviceID     = TestDeviceIDStr
	TestHumanID      agd.HumanID      = TestHumanIDStr
	TestHumanIDLower agd.HumanIDLower = TestHumanIDLowerStr
	TestProfileID    agd.ProfileID    = TestProfileIDStr
)

// TestUpdTime is the common update time for tests.
var TestUpdTime = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

// TestBind includes any IPv4 address.
//
// TODO(a.garipov):  Add to golibs/netutil.
var TestBind = netip.MustParsePrefix("0.0.0.0/0")

// TestRespSzEst is a response-size estimate for tests.
const TestRespSzEst datasize.ByteSize = 1 * datasize.KB
