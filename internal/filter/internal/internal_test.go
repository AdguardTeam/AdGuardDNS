package internal_test

import "strings"

// Common long strings for tests.
//
// TODO(a.garipov):  Move to a new validation package.
var (
	testLongStr = strings.Repeat("a", 200)
)
