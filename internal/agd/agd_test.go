package agd_test

import (
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/testutil"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// Common long strings for tests.
var (
	testLongStr        = strings.Repeat("a", 200)
	testLongStrUnicode = strings.Repeat("ы", 200)
)

// Common IDs for tests.
const (
	testHumanIDStr      = "My-Device-X--10"
	testHumanIDLowerStr = "my-device-x--10"

	testHumanID agd.HumanID = testHumanIDStr
)
