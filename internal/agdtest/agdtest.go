// Package agdtest contains simple mocks for common interfaces and other test
// utilities.
package agdtest

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
