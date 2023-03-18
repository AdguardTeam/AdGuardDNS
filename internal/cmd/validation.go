package cmd

import (
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/golibs/timeutil"
)

// Validation utilities

// validatePositive returns an error if v is not a positive number.  prop is the
// name of the property being checked, used for error messages.
func validatePositive[T numberOrDuration](prop string, v T) (err error) {
	if d, ok := any(v).(timeutil.Duration); ok && d.Duration <= 0 {
		return newMustBePositiveError(prop, v)
	}

	return nil
}

// netipAddr is the type constraint for the types from [netip], which we can
// validate using [validateAddrs].
type netipAddr interface {
	netip.Addr | netip.AddrPort

	IsValid() (ok bool)
}

// validateAddrs returns an error if any of the addrs isn't valid.
//
// TODO(a.garipov): Merge with [validateNonNilIPs].
func validateAddrs[T netipAddr](addrs []T) (err error) {
	for i, a := range addrs {
		if !a.IsValid() {
			return fmt.Errorf("at index %d: invalid addr", i)
		}
	}

	return nil
}
