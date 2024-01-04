// Package agdtest contains simple mocks for common interfaces and other test
// utilities.
package agdtest

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
)

// FilteredResponseTTL is the common filtering response TTL for tests.  It is
// also used by [NewConstructor].
const FilteredResponseTTL = FilteredResponseTTLSec * time.Second

// FilteredResponseTTLSec is the common filtering response TTL for tests, as a
// number to simplify message creation.
const FilteredResponseTTLSec = 10

// NewConstructor returns a standard dnsmsg.Constructor for tests.
func NewConstructor() (c *dnsmsg.Constructor) {
	return dnsmsg.NewConstructor(nil, &dnsmsg.BlockingModeNullIP{}, FilteredResponseTTL)
}

// NewCloner returns a standard dnsmsg.Cloner for tests.
func NewCloner() (c *dnsmsg.Cloner) {
	return dnsmsg.NewCloner(dnsmsg.EmptyClonerStat{})
}

// ContextWithTimeout is a helper that creates a new context with timeout and
// registers ctx's cleanup with t.Cleanup.
//
// TODO(a.garipov): Move to golibs.
func ContextWithTimeout(tb testing.TB, timeout time.Duration) (ctx context.Context) {
	tb.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	tb.Cleanup(cancel)

	return ctx
}
