// Package agdvalidate contains validation utilities.
package agdvalidate

import "fmt"

// FirstNonIDRune returns the first non-printable or non-ASCII rune and its
// index.  If includeSlashes is true, it also looks for slashes.  If there are
// no such runes, i is -1.
func FirstNonIDRune(s string, excludeSlashes bool) (i int, r rune) {
	for i, r = range s {
		if r < '!' || r > '~' || (excludeSlashes && r == '/') {
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

// Inclusion returns an error if n is greater than maxVal or less than minVal.
// unitName is used for error messages, see [UnitByte] and the related
// constants.
func Inclusion(n, minVal, maxVal int, unitName string) (err error) {
	switch {
	case n > maxVal:
		return fmt.Errorf("too long: got %d %s, max %d", n, unitName, maxVal)
	case n < minVal:
		return fmt.Errorf("too short: got %d %s, min %d", n, unitName, minVal)
	default:
		return nil
	}
}
