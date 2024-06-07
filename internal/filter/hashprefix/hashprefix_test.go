package hashprefix_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/testutil"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// testFltListID is the common filtering-list for tests.
const testFltListID = agd.FilterListIDAdultBlocking

// Common hostnames for tests.
const (
	testHost      = "porn.example"
	testReplHost  = "repl.example"
	testOtherHost = "otherporn.example"
)
