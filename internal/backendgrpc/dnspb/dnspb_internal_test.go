package dnspb

import (
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// testTimeout is the common timeout for tests.
const testTimeout = 1 * time.Second

// testBind is the common bind subnet for tests.
var testBind = netip.MustParsePrefix("0.0.0.0/0")

// testErrColl is the common error collector for tests.
var testErrColl = agdtest.NewErrorCollector()

// testLogger is the common logger for tests.
var testLogger = slogutil.NewDiscardLogger()
