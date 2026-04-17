package agdslog

import (
	"fmt"
	"log/slog"
)

// StringerValuer is a wrapper over the [fmt.Stringer] interface.
type StringerValuer[T fmt.Stringer] struct {
	value T
}

// NewStringerValuer returns a [StringerValuer] for v.
func NewStringerValuer[T fmt.Stringer](v T) (s StringerValuer[T]) {
	return StringerValuer[T]{
		value: v,
	}
}

// type check
var _ slog.LogValuer = (*StringerValuer[fmt.Stringer])(nil)

// LogValue implements the [slog.LogValuer] interface for [StringerValuer].
func (s StringerValuer[T]) LogValue() (l slog.Value) {
	return slog.StringValue(s.value.String())
}
