// Package agdtest contains simple mocks for common interfaces and other test
// utilities.
package agdtest

import (
	"net/url"
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

// NewConstructorWithTTL returns a standard *dnsmsg.Constructor for tests, using
// ttl as the TTL for filtered responses.
func NewConstructorWithTTL(tb testing.TB, ttl time.Duration) (c *dnsmsg.Constructor) {
	tb.Helper()

	c, err := dnsmsg.NewConstructor(&dnsmsg.ConstructorConfig{
		Cloner:              NewCloner(),
		BlockingMode:        &dnsmsg.BlockingModeNullIP{},
		StructuredErrors:    NewSDEConfig(true),
		FilteredResponseTTL: ttl,
		EDEEnabled:          true,
	})
	require.NoError(tb, err)

	return c
}

// NewConstructor returns a standard *dnsmsg.Constructor for tests, using
// [FilteredResponseTTL] as the TTL for filtered responses.  The returned
// constructor also has the Structured DNS Errors feature enabled.
func NewConstructor(tb testing.TB) (c *dnsmsg.Constructor) {
	tb.Helper()

	c, err := dnsmsg.NewConstructor(&dnsmsg.ConstructorConfig{
		Cloner:              NewCloner(),
		BlockingMode:        &dnsmsg.BlockingModeNullIP{},
		StructuredErrors:    NewSDEConfig(true),
		FilteredResponseTTL: FilteredResponseTTL,
		EDEEnabled:          true,
	})
	require.NoError(tb, err)

	return c
}

// SDEText is a test Structured DNS Error text.
//
// NOTE: Keep in sync with [NewSDEConfig].
//
// TODO(e.burkov):  Add some helper when this message becomes configurable.
const SDEText = `{` +
	`"j":"Filtering",` +
	`"o":"Test Org",` +
	`"c":["mailto:support@dns.example"]` +
	`}`

// NewSDEConfig returns a standard *dnsmsg.StructuredDNSErrorsConfig for tests.
func NewSDEConfig(enabled bool) (c *dnsmsg.StructuredDNSErrorsConfig) {
	return &dnsmsg.StructuredDNSErrorsConfig{
		Contact: []*url.URL{{
			Scheme: "mailto",
			Opaque: "support@dns.example",
		}},
		Justification: "Filtering",
		Organization:  "Test Org",
		Enabled:       enabled,
	}
}

// NewCloner returns a standard dnsmsg.Cloner for tests.
func NewCloner() (c *dnsmsg.Cloner) {
	return dnsmsg.NewCloner(dnsmsg.EmptyClonerStat{})
}
