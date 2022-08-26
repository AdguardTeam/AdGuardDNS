package dnsmsg

import (
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
)

// Common Errors

// BadECSError is returned by functions that work with EDNS Client Subnet
// option when the data in the option is invalid.
type BadECSError struct {
	Err error
}

// type check
var _ error = BadECSError{}

// Error implements the error interface for BadECSError.
func (err BadECSError) Error() (msg string) {
	return fmt.Sprintf("bad ecs: %s", err.Err)
}

// type check
var _ errors.Wrapper = BadECSError{}

// Unwrap implements the errors.Wrapper interface for BadECSError.
func (err BadECSError) Unwrap() (unwrapped error) {
	return err.Err
}
