package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"golang.org/x/exp/constraints"
)

// validator is the interface for configuration entities that can validate
// themselves.
type validator interface {
	// validate returns an error if the entity isn't valid.
	validate() (err error)
}

// reportPanics reports all panics in Main using the Sentry client, logs them,
// and repanics.  It should be called in a defer.
func reportPanics(ctx context.Context, errColl errcoll.Interface, l *slog.Logger) {
	v := recover()
	if v == nil {
		return
	}

	err := errors.FromRecovered(v)
	l.ErrorContext(ctx, "recovered from panic", slogutil.KeyError, err)
	slogutil.PrintStack(ctx, l, slog.LevelError)

	errColl.Collect(ctx, err)
	errFlushColl, ok := errColl.(errcoll.ErrorFlushCollector)
	if ok {
		errFlushColl.Flush()
	}

	panic(v)
}

// numberOrDuration is the constraint for integer types along with
// [timeutil.Duration].
type numberOrDuration interface {
	constraints.Integer | timeutil.Duration
}

// newNotPositiveError returns an error about the value that must be positive
// but isn't.  prop is the name of the property to mention in the error message.
// The returned error has underlying value of [errors.ErrNotPositive].
func newNotPositiveError[T numberOrDuration](prop string, v T) (err error) {
	if s, ok := any(v).(fmt.Stringer); ok {
		return fmt.Errorf("%s: %w: got %s", prop, errors.ErrNotPositive, s)
	}

	return fmt.Errorf("%s: %w: got %d", prop, errors.ErrNotPositive, v)
}

// newNegativeError returns an error about the value that must be non-negative
// but isn't.  prop is the name of the property to mention in the error message.
// The returned error has underlying value of [errors.ErrNegative].
func newNegativeError[T numberOrDuration](prop string, v T) (err error) {
	if s, ok := any(v).(fmt.Stringer); ok {
		return fmt.Errorf("%s: %w: got %s", prop, errors.ErrNegative, s)
	}

	return fmt.Errorf("%s: %w: got %d", prop, errors.ErrNegative, v)
}
