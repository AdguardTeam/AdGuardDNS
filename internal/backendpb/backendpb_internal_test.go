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
// TODO(a.garipov):  Move the generated code into a separate subpackage and move
// all or most of these into external tests of that package.
const (
	TestAccountIDStr    = "acc1234"
	TestDeviceIDStr     = "dev1234"
	TestHumanIDStr      = "My-Device-X--10"
	TestHumanIDLowerStr = "my-device-x--10"
	TestProfileIDStr    = "prof1234"

	TestAccountID    agd.AccountID    = TestAccountIDStr
	TestDeviceID     agd.DeviceID     = TestDeviceIDStr
	TestHumanID      agd.HumanID      = TestHumanIDStr
	TestHumanIDLower agd.HumanIDLower = TestHumanIDLowerStr
	TestProfileID    agd.ProfileID    = TestProfileIDStr
)

// TestTimeout is the common timeout for tests.
const TestTimeout = 1 * time.Second

var (
	// TestSyncTime is the common update time for tests.
	TestSyncTime = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

	// TestNotBefore is the common not-before time for tests.
	TestNotBefore = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

	// TestNotAfter is the common not-after time for tests.
	TestNotAfter = time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)

	// TestPendingExpire is the common pending-cert expire-time for tests.
	TestPendingExpire = time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)
)

// TestBind includes any IPv4 address.
//
// TODO(a.garipov):  Add to golibs/netutil.
var TestBind = netip.MustParsePrefix("0.0.0.0/0")

// TestLogger is the common logger for tests.
var TestLogger = slogutil.NewDiscardLogger()

// TestRespSzEst is a response-size estimate for tests.
const TestRespSzEst datasize.ByteSize = 1 * datasize.KB
