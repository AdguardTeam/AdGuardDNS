package cmd

import (
	"fmt"

	"github.com/AdguardTeam/golibs/timeutil"
	"golang.org/x/exp/constraints"
)

// Error Helpers

// check is a simple error-checking helper.  It must only be used within Main.
func check(err error) {
	if err != nil {
		panic(err)
	}
}

// coalesceError returns the first non-nil error.  It is named after function
// COALESCE in SQL.  If all errors are nil, it returns nil.
//
// TODO(a.garipov): Consider a similar helper to group errors together to show
// as many errors as possible.
//
// TODO(a.garipov): Think of ways to merge with [aghalg.Coalesce] in AdGuard
// Home.
func coalesceError(errors ...error) (res error) {
	for _, err := range errors {
		if err != nil {
			return err
		}
	}

	return nil
}

// numberOrDuration is the constraint for integer types along with
// timeutil.Duration.
type numberOrDuration interface {
	constraints.Integer | timeutil.Duration
}

// validatePositive returns an error if v is not a positive number.  prop is the
// name of the property being checked, used for error messages.
func validatePositive[T numberOrDuration](prop string, v T) (err error) {
	if d, ok := any(v).(timeutil.Duration); ok && d.Duration <= 0 {
		return newMustBePositiveError(prop, v)
	}

	return nil
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
