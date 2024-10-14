// Package agdtest contains simple mocks for common interfaces and other test
// utilities.
package agdtest

import (
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/stretchr/testify/require"
)

// FilteredResponseTTL is the common filtering response TTL for tests.  It is
// also used by [NewConstructor].
const FilteredResponseTTL = FilteredResponseTTLSec * time.Second

// FilteredResponseTTLSec is the common filtering response TTL for tests, as a
// number to simplify message creation.
const FilteredResponseTTLSec = 10

// NewConstructorWithTTL returns a standard dnsmsg.Constructor for tests, using
// ttl as the TTL for filtered responses.
func NewConstructorWithTTL(tb testing.TB, ttl time.Duration) (c *dnsmsg.Constructor) {
	tb.Helper()

	c, err := dnsmsg.NewConstructor(&dnsmsg.ConstructorConfig{
		Cloner:              NewCloner(),
		BlockingMode:        &dnsmsg.BlockingModeNullIP{},
		FilteredResponseTTL: ttl,
	})
	require.NoError(tb, err)

	return c
}

// NewConstructor returns a standard dnsmsg.Constructor for tests, using
// [FilteredResponseTTL] as the TTL for filtered responses.
func NewConstructor(tb testing.TB) (c *dnsmsg.Constructor) {
	tb.Helper()

	c, err := dnsmsg.NewConstructor(&dnsmsg.ConstructorConfig{
		Cloner:              NewCloner(),
		BlockingMode:        &dnsmsg.BlockingModeNullIP{},
		FilteredResponseTTL: FilteredResponseTTL,
	})
	require.NoError(tb, err)

	return c
}

// NewCloner returns a standard dnsmsg.Cloner for tests.
func NewCloner() (c *dnsmsg.Cloner) {
	return dnsmsg.NewCloner(dnsmsg.EmptyClonerStat{})
}
