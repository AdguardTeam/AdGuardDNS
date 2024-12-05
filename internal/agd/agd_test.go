package agd_test

import (
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
)

// Common long strings for tests.
//
// TODO(a.garipov):  Move to a new validation package.
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
