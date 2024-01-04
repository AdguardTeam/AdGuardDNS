// Package agd contains common entities and interfaces of AdGuard DNS.
package agd

import (
	"fmt"
)

// Common Constants, Types, And Utilities

// firstNonIDRune returns the first non-printable or non-ASCII rune and its
// index.  If slashes is true, it also looks for slashes.  If there are no such
// runes, i is -1.
func firstNonIDRune(s string, slashes bool) (i int, r rune) {
	for i, r = range s {
		if r < '!' || r > '~' || (slashes && r == '/') {
			return i, r
		}
	}

	return -1, 0
}

// Unit name constants.
const (
	UnitByte = "bytes"
	UnitRune = "runes"
)

// ValidateInclusion returns an error if n is greater than max or less than min.
// unitName is used for error messages, see UnitFoo constants.
//
// TODO(a.garipov): Consider switching min and max; the current order seems
// confusing.
func ValidateInclusion(n, max, min int, unitName string) (err error) {
	switch {
	case n > max:
		return fmt.Errorf("too long: got %d %s, max %d", n, unitName, max)
	case n < min:
		return fmt.Errorf("too short: got %d %s, min %d", n, unitName, min)
	default:
		return nil
	}
}
