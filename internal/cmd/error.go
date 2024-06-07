package cmd

import (
	"fmt"

	"github.com/AdguardTeam/golibs/timeutil"
	"golang.org/x/exp/constraints"
)

// Error-handling utilities

// check is a simple error-checking helper.  It must only be used within Main.
func check(err error) {
	if err != nil {
		panic(err)
	}
}

// numberOrDuration is the constraint for integer types along with
// timeutil.Duration.
type numberOrDuration interface {
	constraints.Integer | timeutil.Duration
}

// newMustBePositiveError returns an error about the value that must be positive
// but isn't.  prop is the name of the property to mention in the error message.
func newMustBePositiveError[T numberOrDuration](prop string, v T) (err error) {
	if s, ok := any(v).(fmt.Stringer); ok {
		return fmt.Errorf("%s must be positive, got %s", prop, s)
	}

	return fmt.Errorf("%s must be positive, got %d", prop, v)
}

// newMustBeNonNegativeError returns an error about the value that must be
// non-negative but isn't.  prop is the name of the property to mention in the
// error message.
func newMustBeNonNegativeError[T numberOrDuration](prop string, v T) (err error) {
	if s, ok := any(v).(fmt.Stringer); ok {
		return fmt.Errorf("%s must be non-negative, got %s", prop, s)
	}

	return fmt.Errorf("%s must be non-negative, got %d", prop, v)
}
