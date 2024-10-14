package cmd

import (
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/golibs/timeutil"
)

// validatePositive returns an error if v is not a positive number.  prop is the
// name of the property being checked, used for error messages.
func validatePositive[T numberOrDuration](prop string, v T) (err error) {
	if d, ok := any(v).(timeutil.Duration); ok && d.Duration <= 0 {
		return newNotPositiveError(prop, v)
	}

	return nil
}

// validateProp returns an error wrapped with prop name if the given validator
// func returns an error.
func validateProp(prop string, validator func() error) (err error) {
	err = validator()
	if err != nil {
		return fmt.Errorf("%s: %w", prop, err)
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
