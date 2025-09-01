package agdcache_test

import "time"

// Constants used in tests.
const (
	key = "key"
	val = 123

	nonExistingKey = "nonExistingKey"

	expDuration = 100 * time.Millisecond
)
