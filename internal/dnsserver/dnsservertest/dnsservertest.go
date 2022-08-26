// Package dnsservertest provides convenient helper functions for unit-tests
// in packages related to dnsserver.
package dnsservertest

import (
	"io"
	"os"
	"testing"

	"github.com/AdguardTeam/golibs/log"
)

// DiscardLogOutput runs tests with discarded logger's output.
func DiscardLogOutput(m *testing.M) {
	log.SetOutput(io.Discard)

	os.Exit(m.Run())
}
