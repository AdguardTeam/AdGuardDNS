// Package agdtime contains time-related utilities.
package agdtime

import (
	"encoding"
	"time"

	"github.com/AdguardTeam/golibs/errors"
)

// Clock is an interface for time-related operations.
//
// TODO(a.garipov):  Expand with operations like After or Tick.
//
// TODO(a.garipov):  Move to golibs/timeutil.
type Clock interface {
	Now() (now time.Time)
}

// SystemClock is a [Clock] that uses the functions from package time.
type SystemClock struct{}

// type check
var _ Clock = SystemClock{}

// Now implements the [Clock] interface for SystemClock.
func (SystemClock) Now() (now time.Time) { return time.Now() }

// Location is a wrapper around time.Location that can de/serialize itself from
// and to JSON.
//
// TODO(a.garipov): Move to timeutil.
type Location struct {
	time.Location
}

// LoadLocation is a wrapper around [time.LoadLocation] that returns a
// *Location instead.
func LoadLocation(name string) (l *Location, err error) {
	tl, err := time.LoadLocation(name)
	if err != nil {
		// Don't wrap the error, because this function is a wrapper.
		return nil, err
	}

	return &Location{
		Location: *tl,
	}, nil
}

// UTC returns [time.UTC] as *Location.
func UTC() (l *Location) {
	return &Location{
		Location: *time.UTC,
	}
}

// type check
var _ encoding.TextMarshaler = Location{}

// MarshalText implements the [encoding.TextMarshaler] interface for Location.
func (l Location) MarshalText() (text []byte, err error) {
	return []byte(l.String()), nil
}

var _ encoding.TextUnmarshaler = (*Location)(nil)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface for
// *Location.
func (l *Location) UnmarshalText(b []byte) (err error) {
	defer func() { err = errors.Annotate(err, "unmarshaling location: %w") }()

	tl, err := time.LoadLocation(string(b))
	if err != nil {
		return err
	}

	l.Location = *tl

	return nil
}
