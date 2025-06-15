package forward

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
)

// ctxKey is the type for context keys within this package.
type ctxKey uint8

const (
	ctxKeyNetworkOverride ctxKey = iota
)

// type check
var _ fmt.Stringer = ctxKey(0)

// String implements the [fmt.Stringer] interface for ctxKey.
func (k ctxKey) String() (s string) {
	switch k {
	case ctxKeyNetworkOverride:
		return "ctxKeyNetworkOverride"
	default:
		panic(fmt.Errorf("ctx key: %w: %d", errors.ErrBadEnumValue, k))
	}
}

// panicBadType is a helper that panics with a message about the context key and
// the expected type.
func panicBadType(key ctxKey, v any) {
	panic(fmt.Errorf("bad type for %s: %T(%[2]v)", key, v))
}

// withNetworkOverride returns a copy of the parent context with the network
// override added.
func withNetworkOverride(ctx context.Context, network Network) (withNet context.Context) {
	return context.WithValue(ctx, ctxKeyNetworkOverride, network)
}

// networkOverrideFromContext returns the network override from the context, if
// any.
func networkOverrideFromContext(ctx context.Context) (network Network, ok bool) {
	const key = ctxKeyNetworkOverride

	v := ctx.Value(key)
	if v == nil {
		return NetworkAny, false
	}

	network, ok = v.(Network)
	if !ok {
		panicBadType(key, v)
	}

	return network, true
}
