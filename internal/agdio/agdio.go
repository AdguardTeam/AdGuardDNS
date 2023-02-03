// Package agdio contains extensions and utilities for package io from the
// standard library.
//
// TODO(a.garipov): Move to module golibs.
package agdio

import (
	"fmt"
	"io"

	"github.com/AdguardTeam/golibs/mathutil"
)

// LimitError is returned when the Limit is reached.
type LimitError struct {
	// Limit is the limit that triggered the error.
	Limit int64
}

// Error implements the error interface for *LimitError.
func (err *LimitError) Error() string {
	return fmt.Sprintf("cannot read more than %d bytes", err.Limit)
}

// limitedReader is a wrapper for io.Reader that has a reading limit.
type limitedReader struct {
	r     io.Reader
	limit int64
	n     int64
}

// Read implements the io.Reader interface for *limitedReader.
func (lr *limitedReader) Read(p []byte) (n int, err error) {
	if lr.n == 0 {
		return 0, &LimitError{
			Limit: lr.limit,
		}
	}

	l := mathutil.Min(int64(len(p)), lr.n)
	p = p[:l]

	n, err = lr.r.Read(p)
	lr.n -= int64(n)

	return n, err
}

// LimitReader returns an io.Reader that reads up to n bytes.  Once that limit
// is reached, ErrLimit is returned from limited's Read method.  Method
// Read of limited is not safe for concurrent use.  n must be non-negative.
func LimitReader(r io.Reader, n int64) (limited io.Reader) {
	return &limitedReader{
		r:     r,
		limit: n,
		n:     n,
	}
}
