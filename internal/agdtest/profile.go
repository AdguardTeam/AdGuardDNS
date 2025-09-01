package agdtest

import (
	"reflect"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	gocmp "github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

// AssertEqualProfile compares two values while ignoring internal details of
// some fields of profiles, such as pools.
func AssertEqualProfile(tb testing.TB, want, got any) (ok bool) {
	tb.Helper()

	exportAll := gocmp.Exporter(func(_ reflect.Type) (ok bool) { return true })

	defAccCmp := gocmp.Comparer(func(want, got *access.DefaultProfile) (ok bool) {
		return gocmp.Equal(want.Config(), got.Config(), exportAll)
	})

	diff := gocmp.Diff(want, got, defAccCmp, exportAll)
	if diff == "" {
		return true
	}

	// Use assert.Failf instead of tb.Errorf to get a more consistent error
	// message.
	return assert.Failf(tb, "not equal", "got: %+v\nwant: %+v\ndiff: %s", got, want, diff)
}
