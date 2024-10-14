package hashprefix_test

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
)

// testFltListID is the common filtering-list for tests.
const testFltListID = agd.FilterListIDAdultBlocking

// Common hostnames for tests.
const (
	testHost      = "porn.example"
	testReplHost  = "repl.example"
	testOtherHost = "otherporn.example"
)
