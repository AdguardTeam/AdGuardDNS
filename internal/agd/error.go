package agd

import (
	"fmt"
)

// Common Errors

// ArgumentError is returned by functions when a value of an argument is
// invalid.
type ArgumentError struct {
	// Name is the name of the argument.
	Name string

	// Message is an optional additional message.
	Message string
}

// Error implements the error interface for *ArgumentError.
func (err *ArgumentError) Error() (msg string) {
	if err.Message == "" {
		return fmt.Sprintf("argument %s is invalid", err.Name)
	}

	return fmt.Sprintf("argument %s is invalid: %s", err.Name, err.Message)
}
