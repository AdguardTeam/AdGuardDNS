// Package agdtest contains simple mocks for common interfaces and other test
// utilities.
package agdtest

import (
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
)

// FilteredResponseTTL is the common filtering response TTL for tests.  It is
// also used by [NewConstructor].
const FilteredResponseTTL = 10 * time.Second

// NewConstructor returns a standard dnsmsg.Constructor for tests.
func NewConstructor() (c *dnsmsg.Constructor) {
	return dnsmsg.NewConstructor(&dnsmsg.BlockingModeNullIP{}, FilteredResponseTTL)
}
