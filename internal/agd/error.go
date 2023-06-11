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

// NotACountryError is returned from NewCountry when the string doesn't represent
// a valid country.
type NotACountryError struct {
	// Code is the code presented to NewCountry.
	Code string
}

// Error implements the error interface for *NotACountryError.
func (err *NotACountryError) Error() (msg string) {
	return fmt.Sprintf("%q is not a valid iso 3166-1 alpha-2 code", err.Code)
}

// NotAContinentError is returned from NewContinent when the string doesn't
// represent a valid continent.
type NotAContinentError struct {
	// Code is the code presented to NewContinent.
	Code string
}

// Error implements the error interface for *NotAContinentError.
func (err *NotAContinentError) Error() (msg string) {
	return fmt.Sprintf("%q is not a valid continent code", err.Code)
}
