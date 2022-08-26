// Package agd contains common entities and interfaces of AdGuard DNS.
package agd

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Common Constants, Types, And Utilities

// RequestID is the ID of a request.  It is an opaque, randomly generated
// string.  API users should not rely on it being pseudorandom or
// cryptographically random.
type RequestID string

// NewRequestID returns a new pseudorandom RequestID.  Prefer this to manual
// conversion from other string types.
func NewRequestID() (id RequestID) {
	// Generate a random 16-byte (128-bit) number, encode it into a URL-safe
	// Base64 string, and return it.
	const N = 16

	var idData [N]byte
	_, err := rand.Read(idData[:])
	if err != nil {
		panic(fmt.Errorf("generating random request id: %w", err))
	}

	enc := base64.URLEncoding.WithPadding(base64.NoPadding)
	n := enc.EncodedLen(N)
	idData64 := make([]byte, n)
	enc.Encode(idData64, idData[:])

	return RequestID(idData64)
}

// unit is a convenient alias for struct{}.
type unit = struct{}

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
