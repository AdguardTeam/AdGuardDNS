package agd

import (
	"encoding/base64"
	"fmt"
	"time"

	"golang.org/x/exp/rand"
)

// RequestIDLen is the length of a [RequestID] in bytes.  A RequestID is
// currently a random 16-byte (128-bit) number.
const RequestIDLen = 16

// RequestID is the ID of a request.  It is an opaque, randomly generated
// string.  API users should not rely on it being pseudorandom or
// cryptographically random.
type RequestID [RequestIDLen]byte

// requestIDRand is used to create [RequestID]s.
//
// TODO(a.garipov): Consider making a struct instead of using one global source.
var requestIDRand = rand.New(&rand.LockedSource{})

// InitRequestID initializes the [RequestID] generator.
func InitRequestID() {
	// #nosec G115 -- The Unix epoch time is highly unlikely to be negative.
	requestIDRand.Seed(uint64(time.Now().UnixNano()))
}

// NewRequestID returns a new pseudorandom RequestID.  Prefer this to manual
// conversion from other string types.
func NewRequestID() (id RequestID) {
	_, err := requestIDRand.Read(id[:])
	if err != nil {
		panic(fmt.Errorf("generating random request id: %w", err))
	}

	return id
}

// type check
var _ fmt.Stringer = RequestID{}

// String implements the [fmt.Stringer] interface for RequestID.
func (id RequestID) String() (s string) {
	enc := base64.URLEncoding.WithPadding(base64.NoPadding)
	n := enc.EncodedLen(RequestIDLen)
	idData64 := make([]byte, n)
	enc.Encode(idData64, id[:])

	return string(idData64)
}
