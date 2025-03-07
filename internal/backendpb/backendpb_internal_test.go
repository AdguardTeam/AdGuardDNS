package backendpb

import (
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/c2h5oh/datasize"
)

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

// TestSyncTime is the common update time for tests.
var TestSyncTime = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

// TestBind includes any IPv4 address.
//
// TODO(a.garipov):  Add to golibs/netutil.
var TestBind = netip.MustParsePrefix("0.0.0.0/0")

// TestLogger is the common logger for tests.
var TestLogger = slogutil.NewDiscardLogger()

// TestRespSzEst is a response-size estimate for tests.
const TestRespSzEst datasize.ByteSize = 1 * datasize.KB
